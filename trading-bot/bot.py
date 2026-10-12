"""
Run once per trading day (e.g. Task Scheduler at 12:30 PM Pacific).

  python bot.py            # paper trading, places paper orders
  python bot.py --dry-run  # show what it WOULD do, place nothing
  python bot.py --live     # real money -- also requires ALPACA_PAPER=false in .env

Safety rails:
  * Paper by default. Live needs BOTH the --live flag AND ALPACA_PAPER=false.
  * MAX_TRADE_USD caps any single buy (default $50) no matter what the account holds.
  * Won't trade while the market is closed or while an order is still pending.
  * Keeps a small cash cushion so a notional market order never overdraws.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys

from broker import Broker, load_env
from strategy import compute_signal, decide_action

MIN_ORDER_USD = 1.00  # Alpaca's fractional minimum


def setup_logging() -> logging.Logger:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler("bot.log"), logging.StreamHandler(sys.stdout)],
    )
    return logging.getLogger("bot")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="trade real money")
    ap.add_argument("--dry-run", action="store_true", help="log decisions, place no orders")
    args = ap.parse_args()

    load_env()
    log = setup_logging()

    symbol = os.environ.get("SYMBOL", "SPY")
    sma_days = int(os.environ.get("SMA_DAYS", "200"))
    buffer_pct = float(os.environ.get("BUFFER_PCT", "1.0"))
    max_trade = float(os.environ.get("MAX_TRADE_USD", "50"))
    cushion = float(os.environ.get("CASH_CUSHION_PCT", "2"))

    env_paper = os.environ.get("ALPACA_PAPER", "true").lower() != "false"
    if args.live and env_paper:
        log.error("--live given but ALPACA_PAPER is not 'false' in .env. Refusing.")
        return 2
    paper = not args.live
    mode = "DRY-RUN" if args.dry_run else ("PAPER" if paper else "LIVE")

    broker = Broker(paper=paper)
    acct = broker.account()
    log.info("[%s] %s | equity $%.2f cash $%.2f", mode, symbol, acct["equity"], acct["cash"])

    closes = broker.daily_closes(symbol, sma_days + 5)
    sig = compute_signal(closes, sma_days, buffer_pct)
    pos_val = broker.position_value(symbol)
    action = decide_action(sig["target"], pos_val > 0)
    log.info("close %.2f  SMA%d %.2f  target=%s  position=$%.2f  -> %s",
             sig["last_close"], sma_days, sig["sma"], sig["target"], pos_val, action)

    if action == "NONE":
        return 0
    if not broker.market_open():
        log.info("Market closed; will re-check next run.")
        return 0
    if broker.open_orders(symbol):
        log.info("An order for %s is still open; skipping.", symbol)
        return 0

    if action == "BUY":
        dollars = min(acct["cash"] * (1 - cushion / 100), max_trade)
        if dollars < MIN_ORDER_USD:
            log.warning("Only $%.2f available; below $%.2f minimum.", dollars, MIN_ORDER_USD)
            return 0
        if args.dry_run:
            log.info("Would BUY $%.2f of %s", dollars, symbol)
        else:
            o = broker.buy_notional(symbol, dollars)
            log.info("BUY $%.2f %s submitted (order %s)", dollars, symbol, o.id)

    elif action == "SELL":
        if args.dry_run:
            log.info("Would SELL entire %s position ($%.2f)", symbol, pos_val)
        else:
            o = broker.close_position(symbol)
            log.info("SELL %s submitted (order %s)", symbol, o.id)
    return 0


if __name__ == "__main__":
    sys.exit(main())
