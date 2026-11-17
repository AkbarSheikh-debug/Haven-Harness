import { fetchOnce, type HopRequest } from './web.ts';

/**
 * The separate process behind `web_fetch`. It starts with an empty environment, holds no keys and no state,
 * reads one request from stdin, makes one hop, and writes one result to stdout.
 */
const chunks: Buffer[] = [];
for await (const chunk of process.stdin) chunks.push(chunk as Buffer);

try {
  const request = JSON.parse(Buffer.concat(chunks).toString('utf8')) as HopRequest;
  const result = await fetchOnce(request);
  process.stdout.write(JSON.stringify(result.kind === 'response' ? { ...result, body: result.body.toString('base64') } : result));
} catch (error) {
  process.stdout.write(JSON.stringify({ kind: 'refused', reason: `The fetch failed: ${error instanceof Error ? error.message : 'unknown error'}` }));
}
