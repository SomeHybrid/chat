import asyncio

from encryption import rsa_encrypt, Encryption 


def stringify(data: list[int]) -> str:
    return "".join(chr(char) for char in data)


async def ainput():
    loop = asyncio.get_running_loop()
    try:
        return await loop.run_in_executor(None, input)
    except KeyboardInterrupt:
        raise SystemExit


async def write(writer: asyncio.StreamWriter, encrypt: Encryption):
    while True:
        data = await ainput()
        encrypted_data = encrypt.encrypt(data.encode())

        print("\033[1A", end="")
        print("\033[K", end="")
        print(f"127.0.0.1: {data}")
        writer.write(bytes(encrypted_data))
        await writer.drain()


async def read(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, encrypt: Encryption):
    while True:
        data = await reader.read(8192)
        data = encrypt.encrypt(data)
        if not data:
              writer.close()

        ip = writer.get_extra_info('peername')[0]
        print(f"{ip}: {data.decode()}")


async def handler(
    reader: asyncio.StreamReader, 
    writer: asyncio.StreamWriter, 
):
    public_key = 65537

    mod = await reader.read(4096)
    mod = int.from_bytes(mod, "little")

    tempkey = int.from_bytes(encryption.key, "little")
    tempkey = rsa_encrypt(tempkey, public_key, mod)

    writer.write(tempkey.to_bytes((tempkey.bit_length() + 7) // 8, "little"))
    await writer.drain()
    ip = writer.get_extra_info('peername')[0]
    print(f"{ip} connected.")
    await asyncio.gather(
        read(reader, writer, encryption),
        write(writer, encryption),
    )


async def main():
    server = await asyncio.start_server(
        handler,
        '127.0.0.1',
        8888,
    )

    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    try:
        encryption = Encryption()
        asyncio.run(main())
    except KeyboardInterrupt:
        raise SystemExit
