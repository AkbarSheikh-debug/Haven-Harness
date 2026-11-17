import { parentPort, workerData } from 'node:worker_threads';
import { parseImageHeader } from './image-header.ts';

// Runs apart from the loop, with a memory cap and a timeout, so a hostile file cannot stall or exhaust it.
try {
  parentPort?.postMessage(parseImageHeader(Buffer.from(workerData as Uint8Array)));
} catch {
  parentPort?.postMessage({ error: 'The image header could not be read.' });
}
