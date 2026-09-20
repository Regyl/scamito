import asyncio
import logging

import httpcore
import httpx

from research.flibbertak.scripts import phone_number_supplier
from scamito.util.log import setup_logging

setup_logging()
log = logging.getLogger(__name__)

FRONT_API_URL = "https://flibbertak.ru/front-api"
SEND_SMS_PATH = "/api_main/reg/send_sms/"

client = httpx.AsyncClient(
    headers={"Accept": "application/json", "Content-Type":"application/json"},
    timeout=60,
    limits = httpx.Limits(
        max_connections=50,
        max_keepalive_connections=100,
        keepalive_expiry=10.0,
    )
)

async def send_sms():
    phone = phone_number_supplier.get()
    try:
        log.info(f"{phone}")
        payload = {
            "method": "POST",
            "url": SEND_SMS_PATH,
            "body": {"phone": phone, "utm": {}},
        }
        response = await client.post(url=FRONT_API_URL, json=payload)
        log.info(f"{phone}:{response.status_code}:{response.text}")
        return response
    except Exception as e:
        log.warning(f"error:{phone}:{type(e).__name__}")


async def main(type: str):
    if type == "sync":
        while True:
            await send_sms()
    else:
        tasks = []
        for i in range(20):
            task = asyncio.create_task(send_sms())
            tasks.append(task)

    for task in tasks:
        await task


if __name__ == "__main__":
    asyncio.run(main("sync"))
