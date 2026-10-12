"""Thin wrapper around alpaca-py so the bot logic doesn't touch the SDK directly."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pandas as pd
from alpaca.common.exceptions import APIError
from alpaca.data.enums import DataFeed
from alpaca.data.historical import StockHistoricalDataClient
from alpaca.data.requests import StockBarsRequest
from alpaca.data.timeframe import TimeFrame
from alpaca.trading.client import TradingClient
from alpaca.trading.enums import OrderSide, TimeInForce
from alpaca.trading.requests import MarketOrderRequest


def load_env(path: str = ".env") -> None:
    """Minimal .env loader (KEY=VALUE lines) so we don't need python-dotenv."""
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


class Broker:
    def __init__(self, paper: bool = True):
        key = os.environ.get("ALPACA_API_KEY")
        secret = os.environ.get("ALPACA_SECRET_KEY")
        if not key or not secret:
            raise SystemExit("Set ALPACA_API_KEY and ALPACA_SECRET_KEY in .env")
        self.paper = paper
        self.trading = TradingClient(key, secret, paper=paper)
        self.data = StockHistoricalDataClient(key, secret)

    # ---- market data -------------------------------------------------
    def daily_closes(self, symbol: str, days: int) -> pd.Series:
        """Daily closes, oldest -> newest. Uses the free IEX feed."""
        start = datetime.now(timezone.utc) - timedelta(days=int(days * 1.6) + 10)
        req = StockBarsRequest(symbol_or_symbols=symbol, timeframe=TimeFrame.Day,
                               start=start, feed=DataFeed.IEX)
        df = self.data.get_stock_bars(req).df
        if df.empty:
            raise RuntimeError(f"No bars returned for {symbol}")
        if isinstance(df.index, pd.MultiIndex):
            df = df.xs(symbol, level="symbol")
        return df["close"].sort_index()

    # ---- account -----------------------------------------------------
    def market_open(self) -> bool:
        return bool(self.trading.get_clock().is_open)

    def account(self) -> dict:
        a = self.trading.get_account()
        return {"cash": float(a.cash), "equity": float(a.equity),
                "buying_power": float(a.buying_power), "status": str(a.status)}

    def position_value(self, symbol: str) -> float:
        try:
            return float(self.trading.get_open_position(symbol).market_value)
        except APIError:
            return 0.0

    def open_orders(self, symbol: str) -> int:
        from alpaca.trading.requests import GetOrdersRequest
        from alpaca.trading.enums import QueryOrderStatus
        orders = self.trading.get_orders(GetOrdersRequest(status=QueryOrderStatus.OPEN,
                                                          symbols=[symbol]))
        return len(orders)

    # ---- orders ------------------------------------------------------
    def buy_notional(self, symbol: str, dollars: float):
        req = MarketOrderRequest(symbol=symbol, notional=round(dollars, 2),
                                 side=OrderSide.BUY, time_in_force=TimeInForce.DAY)
        return self.trading.submit_order(req)

    def close_position(self, symbol: str):
        return self.trading.close_position(symbol)
