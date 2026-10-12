"""
Backtest the strategy on real Alpaca history before risking anything.

  python backtest.py                     # SPY, SMA200, last ~8 years
  python backtest.py --symbol QQQ --sma 100 --years 5
  python backtest.py --csv prices.csv    # offline: CSV with Date,Close columns

Note: Alpaca's free IEX feed starts around 2016-2020 depending on symbol,
so very long backtests may need a CSV (e.g. exported from Yahoo Finance).
"""
from __future__ import annotations

import argparse
import os

import pandas as pd

from strategy import backtest


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--symbol", default=os.environ.get("SYMBOL", "SPY"))
    ap.add_argument("--sma", type=int, default=200)
    ap.add_argument("--buffer", type=float, default=1.0, help="hysteresis %% around the SMA")
    ap.add_argument("--years", type=float, default=8)
    ap.add_argument("--cash", type=float, default=50)
    ap.add_argument("--csv", help="Date,Close CSV instead of Alpaca data")
    ap.add_argument("--plot", action="store_true", help="save equity_curve.png")
    args = ap.parse_args()

    if args.csv:
        df = pd.read_csv(args.csv, parse_dates=[0], index_col=0)
        col = next(c for c in df.columns if c.lower().replace(" ", "") in ("close", "adjclose"))
        closes = df[col].sort_index()
    else:
        from broker import Broker, load_env
        load_env()
        closes = Broker(paper=True).daily_closes(args.symbol, int(args.years * 252) + args.sma)

    r = backtest(closes, args.sma, args.buffer, start_cash=args.cash)
    print(f"\n{args.symbol}  SMA{args.sma}  buffer {args.buffer}%   {r['start']} -> {r['end']}")
    print("-" * 56)
    print(f"{'':22}{'Strategy':>16}{'Buy & hold':>16}")
    print(f"{'Final value':22}{'$'+format(r['final_equity'],'.2f'):>16}{'$'+format(r['buy_hold_final'],'.2f'):>16}")
    print(f"{'Total return':22}{format(r['total_return_pct'],'.1f')+'%':>16}{format(r['buy_hold_return_pct'],'.1f')+'%':>16}")
    print(f"{'Worst drawdown':22}{format(r['max_drawdown_pct'],'.1f')+'%':>16}{format(r['buy_hold_max_drawdown_pct'],'.1f')+'%':>16}")
    print(f"{'Strategy CAGR':22}{format(r['cagr_pct'],'.1f')+'%':>16}")
    print(f"{'Trades':22}{r['trades']:>16}")

    if args.plot:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        ax = r["equity_curve"].plot(label="Strategy", figsize=(10, 5))
        r["buy_hold_curve"].plot(ax=ax, label="Buy & hold")
        ax.set_ylabel("Value ($)"); ax.legend(); ax.set_title(f"{args.symbol} SMA{args.sma}")
        plt.tight_layout(); plt.savefig("equity_curve.png")
        print("\nSaved equity_curve.png")


if __name__ == "__main__":
    main()
