# $50 Trend Bot (Alpaca)

A deliberately boring bot: it holds one ETF (SPY by default) while the price is above
its 200-day moving average and moves to cash when it drops below. It trades a handful of
times a year, buys fractional shares by dollar amount, and is built to be safe to leave alone.

**What it is good at:** sitting out long crashes (2008, 2022-style declines), so the worst
drawdown is usually much smaller than just holding.
**What it is bad at:** choppy sideways markets, where it can buy high and sell low a few
times, and it often trails plain buy-and-hold in strong bull markets. This is not
financial advice, and nothing here guarantees a profit.

## Files
| File | What it does |
|---|---|
| `bot.py` | Run once a day. Checks the signal and buys/sells if needed. |
| `backtest.py` | Tests the strategy on historical data. Run this first. |
| `strategy.py` | Signal + backtest math (no broker calls). |
| `broker.py` | Alpaca API wrapper. |
| `test_bot.py` | Offline tests with a fake broker. |

## Setup (Windows)
```powershell
cd trading-bot
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env      # then paste your PAPER keys into .env
python test_bot.py          # should print 4 PASS lines
```
1. Sign up at alpaca.markets. A paper account is free and needs no money.
2. Switch the dashboard to **Paper Trading**, open **API Keys**, generate a key pair, put it in `.env`.

## Step 1: backtest
```powershell
python backtest.py                         # SPY, SMA200
python backtest.py --sma 100 --plot        # try a shorter average, save a chart
python backtest.py --symbol QQQ
```
Compare strategy vs buy & hold on both **return** and **worst drawdown**. If you change
settings, don't just pick whatever won the backtest; that's curve-fitting and rarely holds up.

## Step 2: paper trade (a few months)
```powershell
python bot.py --dry-run     # shows the decision, places nothing
python bot.py               # places PAPER orders
```
Schedule it once per weekday during market hours, e.g. Task Scheduler at 12:30 PM Pacific:
```powershell
schtasks /create /tn "TrendBot" /sc weekly /d MON,TUE,WED,THU,FRI /st 12:30 `
  /tr "cmd /c cd /d C:\path\to\trading-bot && .venv\Scripts\python.exe bot.py"
```
Everything is logged to `bot.log`.

Tip: reset the paper account balance to $50 in the Alpaca dashboard so the paper run
looks like your real one (`MAX_TRADE_USD` also caps buys at $50 either way).

## Step 3: live (only if you want to)
1. Fund a live Alpaca account and generate **live** keys.
2. In `.env`: put in the live keys and set `ALPACA_PAPER=false`.
3. Change the scheduled task to `bot.py --live`.

Both steps are required on purpose; either one alone is refused.

## Safety rails built in
- Paper by default; live needs `--live` **and** `ALPACA_PAPER=false`.
- `MAX_TRADE_USD` caps every buy, whatever the account balance.
- Skips trading when the market is closed or an order is still pending.
- Keeps a small cash cushion so market orders don't overdraw.
- Long-only, no margin, no options.

## Things to know
- Notional orders must be at least $1, so this works fine with $50.
- Alpaca's free data plan uses the IEX feed. Prices can differ by a few cents from the
  consolidated tape, which doesn't matter for a 200-day average.
- Selling at a gain is a taxable event. Alpaca issues a 1099.
- Keep `.env` private; those keys can trade your account.
