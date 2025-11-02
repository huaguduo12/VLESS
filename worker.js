import {
	connect
} from 'cloudflare:sockets';


const dohCache = new Map(); // 用于缓存DNS查询结果

/**
 * 使用DOH解析域名，并缓存结果
 * @param {string} domain 需要解析的域名
 * @param {Array<string>} servers DOH服务器列表
 * @returns {Promise<string>} 解析成功返回IP地址，否则返回原域名
 */
async function resolveDomainOverDoH(domain, servers) {
	const cached = dohCache.get(domain);
	if (cached && cached.expires > Date.now()) {
		return cached.ip;
	}

	try {
		const queries = servers.map(server =>
			fetch(`${server}?name=${domain}&type=A`, {
				headers: { 'accept': 'application/dns-json' }
			}).then(res => res.json())
		);

		const result = await Promise.any(queries);

		const answer = result?.Answer?.find(a => a.type === 1); // type 1 is A record
		if (answer && answer.data) {
			const ip = answer.data;
			const ttl = answer.TTL || 300;
			dohCache.set(domain, {
				ip: ip,
				expires: Date.now() + ttl * 1000
			});
			console.log(`DOH resolved ${domain} -> ${ip}`);
			return ip;
		}
	} catch (error) {
		console.error(`DOH resolution failed for ${domain}:`, error);
	}

	return domain;
}

export default {
	async fetch(req, env) {
		const u = new URL(req.url); 
		const path = u.pathname.slice(1);
		const UUID = env.UUID || ''; // 你的UUID
		const SOCKS5 = env.SOCKS5 || ''; // SOCKS5代理, 格式: 'user:pass@host:port', 留空则禁用
		const ENABLE_FLOW_CONTROL = (env.ENABLE_FLOW_CONTROL || 'false').toLowerCase() === 'false';
		const FLOW_CONTROL_CHUNK_SIZE = env.FLOW_CONTROL_CHUNK_SIZE || 64 * 1024;
		const ENABLE_DOH = (env.ENABLE_DOH || 'false').toLowerCase() === 'true';
		const DOH_SERVERS = [
			"https://dns.google/resolve",
			"https://cloudflare-dns.com/dns-query"
		];

		if (path.startsWith('doh-test/')) {
			const domainToTest = path.substring('doh-test/'.length);
			if (domainToTest) {
				console.log(`Performing DOH test for: ${domainToTest}`);
				const ip = await resolveDomainOverDoH(domainToTest, DOH_SERVERS);
				return new Response(`DOH Test Result for: ${domainToTest}\nResolved IP: ${ip}\n\nWorker is working correctly.`, {
					status: 200,
					headers: { 'Content-Type': 'text/plain; charset=utf-8' },
				});
			}
		}

		if (req.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
			if (!UUID) {
				return new Response('缺少 UUID 配置', { status: 403 });
			}
			
			const [client, ws] = Object.values(new WebSocketPair());
			ws.accept();

			if (u.pathname.includes('%3F')) {
				const decoded = decodeURIComponent(u.pathname);
				const queryIndex = decoded.indexOf('?');
				if (queryIndex !== -1) {
					u.search = decoded.substring(queryIndex);
					u.pathname = decoded.substring(0, queryIndex);
				}
			}
			
			let s5Param = u.searchParams.get('s5');
			let proxyParam = u.searchParams.get('proxyip');
			let pathBasedOrder = null;

			if (path.startsWith('socks5://')) {
				s5Param = path.substring('socks5://'.length);
				pathBasedOrder = ['s5'];
			}
			else if (path.startsWith('proxyip=')) {
				proxyParam = path.substring('proxyip='.length);
				pathBasedOrder = ['direct', 'proxy'];
			}
			else if (path.startsWith('socks5=')) {
				s5Param = path.substring('socks5='.length);
				pathBasedOrder = ['direct', 's5'];
			}

			const effectiveS5Config = s5Param || SOCKS5;
            const socks5 = effectiveS5Config && effectiveS5Config.includes('@') ? (() => {
                const [cred, server] = effectiveS5Config.split('@');
                const [user, pass] = cred.split(':');
                const [host, port = 443] = server.split(':');
                return { user, pass, host, port: +port };
            })() : null;

			const PROXY_IP = proxyParam ? String(proxyParam) : (env.PROXYIP || 'bpb.yousef.isegaro.com'); // 从环境变量读取默认值

			const getOrder = () => {
				if (pathBasedOrder) return pathBasedOrder;
				const mode = u.searchParams.get('mode') || 'auto';
				if (mode === 'proxy') return ['direct', 'proxy'];
				if (mode !== 'auto') return [mode];
				
				const order = [];
				const searchStr = u.search.slice(1);
				for (const pair of searchStr.split('&')) {
					const key = pair.split('=')[0];
					if (key === 'direct') order.push('direct');
					else if (key === 's5') order.push('s5');
					else if (key === 'proxyip') order.push('proxy');
				}
				
				if (order.includes('s5') && !order.includes('direct')) order.unshift('direct');
				if (order.includes('proxy') && !order.includes('direct')) order.unshift('direct');
				
				return order.length ? order : ['direct', 's5', 'proxy'];
			};

			let remote = null, udpWriter = null, isDNS = false;

			const socks5Connect = async (targetHost, targetPort) => {
				const sock = connect({ hostname: socks5.host, port: socks5.port });
				await sock.opened;
				const w = sock.writable.getWriter();
				const r = sock.readable.getReader();
				await w.write(new Uint8Array([5, 2, 0, 2]));
				const auth = (await r.read()).value;
				if (auth[1] === 2 && socks5.user) {
					const user = new TextEncoder().encode(socks5.user);
					const pass = new TextEncoder().encode(socks5.pass);
					await w.write(new Uint8Array([1, user.length, ...user, pass.length, ...pass]));
					await r.read();
				}
				const domain = new TextEncoder().encode(targetHost);
				await w.write(new Uint8Array([5, 1, 0, 3, domain.length, ...domain, targetPort >> 8, targetPort & 0xff]));
				await r.read();
				w.releaseLock();
				r.releaseLock();
				return sock;
			};

			new ReadableStream({
				start(ctrl) {
					ws.addEventListener('message', e => ctrl.enqueue(e.data));
					ws.addEventListener('close', () => { remote?.close(); ctrl.close(); });
					ws.addEventListener('error', () => { remote?.close(); ctrl.error(); });
					const early = req.headers.get('sec-websocket-protocol');
					if (early) {
						try {
							ctrl.enqueue(Uint8Array.from(atob(early.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)).buffer);
						} catch {}
					}
				}
			}).pipeTo(new WritableStream({
				async write(data) {
					if (isDNS) return udpWriter?.write(data);
					if (remote) {
						const w = remote.writable.getWriter();
						await w.write(data);
						w.releaseLock();
						return;
					}
					if (data.byteLength < 24) return;

					// --- START: 改动点 - 仅使用静态UUID验证 ---
					const uuidBytes = new Uint8Array(data.slice(1, 17));
					const expectedUUID = UUID.replace(/-/g, '');
					let isValid = false;

					if (expectedUUID.length === 32) {
						let match = true;
						for (let i = 0; i < 16; i++) {
							if (uuidBytes[i] !== parseInt(expectedUUID.substr(i * 2, 2), 16)) {
								match = false;
								break;
							}
						}
						isValid = match;
					}

					if (!isValid) {
						return ws.close(1008, 'Invalid UUID'); 
					}

					const view = new DataView(data);
					const optLen = view.getUint8(17);
					const cmd = view.getUint8(18 + optLen);
					if (cmd !== 1 && cmd !== 2) return;

					let pos = 19 + optLen;
					const port = view.getUint16(pos);
					const type = view.getUint8(pos + 2);
					pos += 3;

					let addr = '';
					if (type === 1) {
						addr = `${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
						pos += 4;
					} else if (type === 2) {
						const len = view.getUint8(pos++);
						const domain = new TextDecoder().decode(data.slice(pos, pos + len));
						pos += len;
						addr = ENABLE_DOH ? await resolveDomainOverDoH(domain, DOH_SERVERS) : domain;
					} else if (type === 3) {
						const ipv6 = [];
						for (let i = 0; i < 8; i++, pos += 2) ipv6.push(view.getUint16(pos).toString(16));
						addr = ipv6.join(':');
					} else return;

					const header = new Uint8Array([data[0], 0]);
					const payload = data.slice(pos);

					if (cmd === 2) { // UDP DNS
						if (port !== 53) return;
						isDNS = true;
						let sent = false;
						const { readable, writable } = new TransformStream({
							transform(chunk, ctrl) {
								for (let i = 0; i < chunk.byteLength;) {
									const len = new DataView(chunk.slice(i, i + 2)).getUint16(0);
									ctrl.enqueue(chunk.slice(i + 2, i + 2 + len));
									i += 2 + len;
								}
							}
						});
						readable.pipeTo(new WritableStream({
							async write(query) {
								try {
									const resp = await fetch('https://1.1.1.1/dns-query', {
										method: 'POST',
										headers: { 'content-type': 'application/dns-message' },
										body: query
									});
									if (ws.readyState === 1) {
										const result = new Uint8Array(await resp.arrayBuffer());
										ws.send(new Uint8Array([...(sent ? [] : header), result.length >> 8, result.length & 0xff, ...result]));
										sent = true;
									}
								} catch {}
							}
						}));
						udpWriter = writable.getWriter();
						return udpWriter.write(payload);
					}

					let sock = null;
					for (const method of getOrder()) {
						try {
							if (method === 'direct') {
								sock = connect({ hostname: addr, port });
								await sock.opened;
								break;
							} else if (method === 's5' && socks5) {
								sock = await socks5Connect(addr, port);
								break;
							} else if (method === 'proxy' && PROXY_IP) {
								const [ph, pp = port] = PROXY_IP.split(':');
								sock = connect({ hostname: ph, port: +pp || port });
								await sock.opened;
								break;
							}
						} catch {}
					}

					if (!sock) return;

					remote = sock;
					const w = sock.writable.getWriter();
					await w.write(payload);
					w.releaseLock();

					let sent = false;
					sock.readable.pipeTo(new WritableStream({
						write(chunk) {
							if (ws.readyState !== 1) return;
							const dataToSend = sent ? chunk : new Uint8Array([...header, ...new Uint8Array(chunk)]);
							sent = true;

							if (ENABLE_FLOW_CONTROL && dataToSend.length > FLOW_CONTROL_CHUNK_SIZE) {
								let offset = 0;
								while (offset < dataToSend.length) {
									const slice = dataToSend.slice(offset, offset + FLOW_CONTROL_CHUNK_SIZE);
									if (ws.readyState === 1) {
										ws.send(slice);
									} else {
										break;
									}
									offset += FLOW_CONTROL_CHUNK_SIZE;
								}
							} else {
								ws.send(dataToSend);
							}
						},
						close: () => { if (ws.readyState === 1) ws.close(); },
						abort: () => { if (ws.readyState === 1) ws.close(); }
					})).catch(() => { if (ws.readyState === 1) ws.close(); });
				}
			})).catch(() => {});

			return new Response(null, { status: 101, webSocket: client });
		}

		return Response.redirect('https://t.me/jiliankeji', 302);
	}

};
