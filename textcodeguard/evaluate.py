import json, sys, time
from collections import defaultdict
from textcodeguard.guard import guard

def prf(tp, fp, fn):
    p = tp/(tp+fp) if tp+fp else 0.0
    r = tp/(tp+fn) if tp+fn else 0.0
    f = 2*p*r/(p+r) if p+r else 0.0
    return p, r, f

def main(path):
    rows = [json.loads(l) for l in open(path, encoding="utf-8-sig") if l.strip()]
    per_cat = defaultdict(lambda: {"tp":0,"fp":0,"fn":0})
    overall = {"tp":0,"fp":0,"fn":0,"tn":0}
    lat = []
    for r in rows:
        t0 = time.perf_counter()
        out = guard(r["code"])
        lat.append((time.perf_counter()-t0)*1000)
        gb = r["verdict"]=="block"; pb = out["verdict"]=="block"
        gc = set(r.get("categories",[])); pc = set(out.get("categories",[]))
        if gb and pb: overall["tp"]+=1
        elif not gb and pb: overall["fp"]+=1
        elif gb and not pb: overall["fn"]+=1
        else: overall["tn"]+=1
        for c in gc|pc:
            if c in gc and c in pc: per_cat[c]["tp"]+=1
            elif c not in gc and c in pc: per_cat[c]["fp"]+=1
            elif c in gc and c not in pc: per_cat[c]["fn"]+=1
    lat.sort()
    q = lambda x: lat[min(len(lat)-1, int(x*len(lat)))]
    print(f"{'category':<28}{'P':>6}{'R':>6}{'F1':>6}")
    for c,m in sorted(per_cat.items()):
        P,R,F = prf(m["tp"],m["fp"],m["fn"])
        print(f"{c:<28}{P:>6.2f}{R:>6.2f}{F:>6.2f}")
    P,R,F = prf(overall["tp"],overall["fp"],overall["fn"])
    acc = (overall["tp"]+overall["tn"])/len(rows)
    print(f"\nOVERALL acc={acc:.3f} P={P:.3f} R={R:.3f} F1={F:.3f} n={len(rows)}")
    print(f"LATENCY p50={q(.5):.2f}ms p95={q(.95):.2f}ms max={max(lat):.2f}ms")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv)>1 else "dev.jsonl")
