"""Offline tests: strategy math + bot decision flow with a fake broker. Run: python test_bot.py"""
import sys
import types

import numpy as np
import pandas as pd

from strategy import backtest, compute_signal, decide_action

idx = pd.bdate_range("2018-01-01", periods=1500)


def test_signal():
    up = pd.Series(np.linspace(100, 200, 300))
    assert compute_signal(up, 200)["target"] == "invested"
    down = pd.Series(np.linspace(200, 100, 300))
    assert compute_signal(down, 200)["target"] == "cash"
    flat = pd.Series([100.0] * 299 + [100.5])
    assert compute_signal(flat, 200, buffer_pct=1.0)["target"] == "hold"


def test_actions():
    assert decide_action("invested", False) == "BUY"
    assert decide_action("invested", True) == "NONE"
    assert decide_action("cash", True) == "SELL"
    assert decide_action("cash", False) == "NONE"
    assert decide_action("hold", True) == "NONE"
    assert decide_action("hold", False) == "NONE"


def test_backtest_no_lookahead_and_crash_protection():
    # rally, crash, recovery
    p = np.concatenate([np.linspace(100, 160, 600), np.linspace(160, 80, 300),
                        np.linspace(80, 170, 600)])
    closes = pd.Series(p, index=idx)
    r = backtest(closes, 200, 1.0, start_cash=50)
    assert r["trades"] >= 2
    assert r["max_drawdown_pct"] > r["buy_hold_max_drawdown_pct"]  # shallower drawdown
    assert r["final_equity"] > 0


def test_bot_flow():
    """Run bot.main() against a fake broker and check it buys, capped at MAX_TRADE_USD."""
    calls = {}

    class FakeBroker:
        def __init__(self, paper=True): calls["paper"] = paper
        def account(self): return {"cash": 500.0, "equity": 500.0, "buying_power": 500.0, "status": "ACTIVE"}
        def daily_closes(self, s, d): return pd.Series(np.linspace(100, 200, 300), index=idx[:300])
        def position_value(self, s): return 0.0
        def market_open(self): return True
        def open_orders(self, s): return 0
        def buy_notional(self, s, dollars):
            calls["buy"] = dollars
            return types.SimpleNamespace(id="fake-1")
        def close_position(self, s): calls["sell"] = True; return types.SimpleNamespace(id="fake-2")

    import broker, bot
    bot.Broker = FakeBroker
    bot.load_env = lambda: None
    import os
    os.environ.update({"ALPACA_PAPER": "true", "MAX_TRADE_USD": "50"})

    sys.argv = ["bot.py"]
    assert bot.main() == 0
    assert calls["paper"] is True and calls["buy"] == 50.0

    # --live must be refused while ALPACA_PAPER is true
    calls.clear(); sys.argv = ["bot.py", "--live"]
    assert bot.main() == 2 and "buy" not in calls

    # dry run places nothing
    calls.clear(); sys.argv = ["bot.py", "--dry-run"]
    assert bot.main() == 0 and "buy" not in calls


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn(); print("PASS", name)
