
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
	// 1. 检查缓存中是否有有效的记录
	const cached = dohCache.get(domain);
	if (cached && cached.expires > Date.now()) {
		return cached.ip;
	}

	// 2. 并发向所有DOH服务器发送请求，看谁最快返回
	try {
		const queries = servers.map(server =>
			fetch(`${server}?name=${domain}&type=A`, { // 只查询A记录 (IPv4)
				headers: { 'accept': 'application/dns-json' }
			}).then(res => res.json())
		);

		const result = await Promise.any(queries);

		const answer = result?.Answer?.find(a => a.type === 1); // type 1 is A record
		if (answer && answer.data) {
			const ip = answer.data;
			const ttl = answer.TTL || 300; // 默认缓存5分钟
			
			// 3. 将成功的结果存入缓存
			dohCache.set(domain, {
				ip: ip,
				expires: Date.now() + ttl * 1000
			});
			
			console.log(`DOH resolved ${domain} -> ${ip}`);
			return ip;
		}
	} catch (error) {
		// 如果所有查询都失败，则不做任何事
		console.error(`DOH resolution failed for ${domain}:`, error);
	}

	// 4. 如果解析失败，则返回原域名，让系统走默认DNS
	return domain;
}

export default {
	async fetch(req, env) { // env 参数现在可以忽略了
		// --- START: 在这里直接写入你的配置 ---
		const u = new URL(req.url); 
        const path = u.pathname.slice(1);

		const UUID = 'e35859af-99b8-43f3-9e6f-a09a95b7c61c'; // 你的UUID留空

		const SOCKS5 = '';
		const ENABLE_FLOW_CONTROL = false; // 是否启用流量控制, true 为启用, false 为关闭
		const FLOW_CONTROL_CHUNK_SIZE = 64 * 1024;
		const ENABLE_DOH = false; // 是否启用DOH, true 为启用, false 为关闭
		const DOH_SERVERS = [
			"https://dns.google/resolve",       // Google Public DNS
			"https://cloudflare-dns.com/dns-query" // Cloudflare DNS
		];

		if (path.startsWith('doh-test/')) {
			const domainToTest = path.substring('doh-test/'.length);
			if (domainToTest) {
				console.log(`Performing DOH test for: ${domainToTest}`);
				const ip = await resolveDomainOverDoH(domainToTest, DOH_SERVERS);
				// 直接返回测试结果，不走WebSocket流程
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
			let pathBasedOrder = null; // 用于存储路径快捷方式强制设定的连接顺序

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
                return {
                    user,
                    pass,
                    host,
                    port: +port
                };
            })() : null;
			const PROXY_IP = proxyParam ? String(proxyParam) : 'bpb.yousef.isegaro.com';

			const getOrder = () => {
				if (pathBasedOrder) {
					return pathBasedOrder;
				}

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
				
				if (order.includes('s5') && !order.includes('direct')) {
					order.unshift('direct');
				}
				if (order.includes('proxy') && !order.includes('direct')) {
					order.unshift('direct');
				}

				return order.length ? order : ['direct', 's5', 'proxy'];
			};

			let remote = null,
				udpWriter = null,
				isDNS = false;

			const socks5Connect = async (targetHost, targetPort) => {
				const sock = connect({
					hostname: socks5.host,
					port: socks5.port
				});
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
				await w.write(new Uint8Array([5, 1, 0, 3, domain.length, ...domain, targetPort >> 8,
					targetPort & 0xff
				]));
				await r.read();
				w.releaseLock();
				r.releaseLock();
				return sock;
			};

			new ReadableStream({
				start(ctrl) {
					ws.addEventListener('message', e => ctrl.enqueue(e.data));
					ws.addEventListener('close', () => {
						remote?.close();
						ctrl.close();
					});
					ws.addEventListener('error', () => {
						remote?.close();
						ctrl.error();
					});

					const early = req.headers.get('sec-websocket-protocol');
					if (early) {
						try {
							ctrl.enqueue(Uint8Array.from(atob(early.replace(/-/g, '+').replace(/_/g, '/')),
								c => c.charCodeAt(0)).buffer);
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
						addr =
							`${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
						pos += 4;
					} else if (type === 2) { // 类型2代表目标地址是域名
						const len = view.getUint8(pos++);
						const domain = new TextDecoder().decode(data.slice(pos, pos + len));
						pos += len;
						
						if (ENABLE_DOH) {
							// 如果启用了DOH，则调用新函数来解析域名
							addr = await resolveDomainOverDoH(domain, DOH_SERVERS);
						} else {
							// 否则，保持原样
							addr = domain;
						}
						
					} else if (type === 3) {
						const ipv6 = [];
						for (let i = 0; i < 8; i++, pos += 2) ipv6.push(view.getUint16(pos)
							.toString(16));
						addr = ipv6.join(':');
					} else return;

					const header = new Uint8Array([data[0], 0]);
					const payload = data.slice(pos);

					// UDP DNS
					if (cmd === 2) {
						if (port !== 53) return;
						isDNS = true;
						let sent = false;
						const {
							readable,
							writable
						} = new TransformStream({
							transform(chunk, ctrl) {
								for (let i = 0; i < chunk.byteLength;) {
									const len = new DataView(chunk.slice(i, i + 2))
										.getUint16(0);
									ctrl.enqueue(chunk.slice(i + 2, i + 2 + len));
									i += 2 + len;
								}
							}
						});

						readable.pipeTo(new WritableStream({
							async write(query) {
								try {
									const resp = await fetch(
										'https://1.1.1.1/dns-query', {
											method: 'POST',
											headers: {
												'content-type': 'application/dns-message'
											},
											body: query
										});
									if (ws.readyState === 1) {
										const result = new Uint8Array(await resp
											.arrayBuffer());
										ws.send(new Uint8Array([...(sent ? [] :
												header), result
											.length >> 8, result
											.length & 0xff, ...result
										]));
										sent = true;
									}
								} catch {}
							}
						}));
						udpWriter = writable.getWriter();
						return udpWriter.write(payload);
					}

					// TCP连接
					let sock = null;
					for (const method of getOrder()) {
						try {
							if (method === 'direct') {
								sock = connect({
									hostname: addr,
									port
								});
								await sock.opened;
								break;
							} else if (method === 's5' && socks5) {
								sock = await socks5Connect(addr, port);
								break;
							} else if (method === 'proxy' && PROXY_IP) {
								const [ph, pp = port] = PROXY_IP.split(':');
								sock = connect({
									hostname: ph,
									port: +pp || port
								});
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
							// 首先，检查WebSocket连接是否仍然处于打开状态
							if (ws.readyState !== 1) {
								return;
							}

							// 准备要发送的完整数据。第一次发送时，需要在数据前加上2字节的header
							const dataToSend = sent ? chunk : new Uint8Array([...header, ...new Uint8Array(chunk)]);
							sent = true; // 标记header已发送，后续不再添加

							// --- START: 这里是新增的流量控制核心逻辑 ---
							if (ENABLE_FLOW_CONTROL && dataToSend.length > FLOW_CONTROL_CHUNK_SIZE) {
								// 如果启用了流控，并且数据大小超过了我们设定的分块大小，则进行分块发送
								let offset = 0;
								while (offset < dataToSend.length) {
									const slice = dataToSend.slice(offset, offset + FLOW_CONTROL_CHUNK_SIZE);
									// 每次发送前都检查连接状态
									if (ws.readyState === 1) {
										ws.send(slice);
									} else {
										break; // 如果在发送过程中连接断开，则立即停止
									}
									offset += FLOW_CONTROL_CHUNK_SIZE;
								}
							} else {
								// 如果未启用流控，或者数据本身就很小，则直接一次性发送
								ws.send(dataToSend);
							}

						},
						close: () => {
							if (ws.readyState === 1) ws.close();
						},
						abort: () => {
							if (ws.readyState === 1) ws.close();
						}
					})).catch(() => {
						// 捕获可能发生的错误，例如远程连接被重置
						if (ws.readyState === 1) ws.close();
					});
			}
			})).catch(() => {});

			return new Response(null, {
				status: 101,
				webSocket: client
			});
		}

		return Response.redirect('https://t.me/jiliankeji', 302);
	}
};
