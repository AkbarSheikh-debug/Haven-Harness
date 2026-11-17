import { parentPort, workerData } from 'node:worker_threads';
import { scanSync, type ExtraPattern, type ThreatScope } from './threat.ts';

const { texts, scope, extra } = workerData as { texts: string[]; scope: ThreatScope; extra: ExtraPattern[] };
parentPort?.postMessage(scanSync(texts, scope, extra));
