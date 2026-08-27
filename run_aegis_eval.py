# Full Evaluation Runner on aegis2.jsonl
import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try: sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except: pass
import json, time
import multiprocessing as mp
from collections import defaultdict
from pathlib import Path

WORKSPACE = Path('.')
from classifier.service import ClassifierService

_worker_service = None
def init_worker():
    global _worker_service
    _worker_service = ClassifierService()

def evaluate_sample(sample):
    global _worker_service
    prompt = sample.get('prompt', '')
    expected = sample.get('expected', '')
    split = sample.get('split', 'unknown')
    evidence = _worker_service.classify(prompt)
    pred = evidence.classification.value
    return {
        'id': sample.get('id'),
        'split': split,
        'expected': expected,
        'predicted': pred,
        'is_tp': (expected == 'RESTRICTED' and pred == 'RESTRICTED'),
        'is_tn': (expected == 'NORMAL' and pred == 'NORMAL'),
        'is_fp': (expected == 'NORMAL' and pred == 'RESTRICTED'),
        'is_fn': (expected == 'RESTRICTED' and pred == 'NORMAL'),
    }

if __name__ == '__main__':
    print('Loading all records from aegis2.jsonl...')
    t0 = time.time()
    records = []
    with open('aegis2.jsonl', 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
    total = len(records)
    print(f'Loaded {total:,} records in {time.time()-t0:.2f}s.')
    num_workers = min(8, mp.cpu_count() or 4)
    print(f'Executing parallel evaluation using {num_workers} CPU workers...')
    t_start = time.time()
    with mp.Pool(processes=num_workers, initializer=init_worker) as pool:
        results = pool.map(evaluate_sample, records, chunksize=128)
    t_total = time.time() - t_start
    throughput = total / t_total
    tp = sum(1 for r in results if r['is_tp'])
    tn = sum(1 for r in results if r['is_tn'])
    fp = sum(1 for r in results if r['is_fp'])
    fn = sum(1 for r in results if r['is_fn'])
    acc = (tp + tn) / total
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
    fpr = fp / (tn + fp) if (tn + fp) > 0 else 0.0
    fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0
    print('='*70)
    print('                 AEGIS-2.0 BENCHMARK EVALUATION RESULTS')
    print('='*70)
    print(f'Total Evaluated:      {total:,}')
    print(f'Throughput:           {throughput:.2f} samples/sec (Time: {t_total:.2f}s)')
    print(f'True Positives (TP):  {tp:,}')
    print(f'True Negatives (TN):  {tn:,}')
    print(f'False Positives (FP): {fp:,} ({fpr*100:.2f}%)')
    print(f'False Negatives (FN): {fn:,} ({fnr*100:.2f}%)')
    print('-'*70)
    print(f'ACCURACY:             {acc*100:6.2f}%')
    print(f'PRECISION:            {prec*100:6.2f}%')
    print(f'RECALL (Safety):      {rec*100:6.2f}%')
    print(f'F1-SCORE:             {f1*100:6.2f}%')
    print('='*70)
