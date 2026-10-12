"""
Strategy logic -- pure functions, no broker calls, so it's easy to test and backtest.

Default strategy: trend filter on one ETF.
  * If yesterday's close is ABOVE its N-day simple moving average -> be invested.
  * If it's BELOW -> sit in cash.
At most one trade every few weeks, so commissions/PDT rules aren't an issue
and a $50 account isn't eaten alive by spreads.
"""
from __future__ import annotations

import pandas as pd


def compute_signal(closes: pd.Series, sma_days: int, buffer_pct: float = 0.0) -> dict:
    """Return the desired state given a series of daily closes (oldest -> newest).

    buffer_pct adds hysteresis: price must clear the SMA by this % to flip,
    which cuts down on whipsaw trades when price hugs the average.
    """
    closes = closes.dropna()
    if len(closes) < sma_days:
        raise ValueError(f"Need at least {sma_days} daily bars, got {len(closes)}")

    sma = closes.rolling(sma_days).mean().iloc[-1]
    last = closes.iloc[-1]
    upper = sma * (1 + buffer_pct / 100)
    lower = sma * (1 - buffer_pct / 100)

    if last > upper:
        target = "invested"
    elif last < lower:
        target = "cash"
    else:
        target = "hold"  # inside the buffer band: keep whatever we have

    return {"last_close": float(last), "sma": float(sma), "target": target}


def decide_action(target: str, has_position: bool) -> str:
    """Map desired state + current state to an action: BUY, SELL or NONE."""
    if target == "invested" and not has_position:
        return "BUY"
    if target == "cash" and has_position:
        return "SELL"
    return "NONE"


def backtest(closes: pd.Series, sma_days: int, buffer_pct: float = 0.0,
             start_cash: float = 50.0, slippage_pct: float = 0.05) -> dict:
    """Simulate the strategy on daily closes.

    Signal is computed on day t's close and executed at day t+1's close
    (no look-ahead). slippage_pct is charged on every trade.
    """
    closes = closes.dropna()
    cash, shares, invested = start_cash, 0.0, False
    trades, equity = 0, []
    slip = slippage_pct / 100

    sma = closes.rolling(sma_days).mean()
    pending = None
    for i in range(len(closes)):
        price = closes.iloc[i]

        # execute yesterday's decision at today's close
        if pending == "BUY":
            shares = cash * (1 - slip) / price
            cash, invested, trades = 0.0, True, trades + 1
        elif pending == "SELL":
            cash = shares * price * (1 - slip)
            shares, invested, trades = 0.0, False, trades + 1
        pending = None

        if not pd.isna(sma.iloc[i]):
            upper = sma.iloc[i] * (1 + buffer_pct / 100)
            lower = sma.iloc[i] * (1 - buffer_pct / 100)
            target = "invested" if price > upper else "cash" if price < lower else "hold"
            act = decide_action(target, invested)
            pending = act if act != "NONE" else None

        equity.append(cash + shares * price)

    eq = pd.Series(equity, index=closes.index)
    bh = start_cash * closes / closes.iloc[sma_days - 1]  # buy & hold from first signal day
    bh = bh.iloc[sma_days - 1:]
    eq_live = eq.iloc[sma_days - 1:]

    def max_dd(s: pd.Series) -> float:
        return float(((s / s.cummax()) - 1).min() * 100)

    years = max((eq_live.index[-1] - eq_live.index[0]).days / 365.25, 1e-9)
    return {
        "start": str(eq_live.index[0].date()),
        "end": str(eq_live.index[-1].date()),
        "final_equity": round(float(eq_live.iloc[-1]), 2),
        "total_return_pct": round((eq_live.iloc[-1] / start_cash - 1) * 100, 2),
        "cagr_pct": round(((eq_live.iloc[-1] / start_cash) ** (1 / years) - 1) * 100, 2),
        "max_drawdown_pct": round(max_dd(eq_live), 2),
        "trades": trades,
        "buy_hold_final": round(float(bh.iloc[-1]), 2),
        "buy_hold_return_pct": round((bh.iloc[-1] / start_cash - 1) * 100, 2),
        "buy_hold_max_drawdown_pct": round(max_dd(bh), 2),
        "equity_curve": eq_live,
        "buy_hold_curve": bh,
    }
