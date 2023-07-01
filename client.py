import asyncio

from server import write, read
from encryption import rsa_keygen, rsa_encrypt, Encryption


async def client(host: str):
    print(f"Connecting to {host}...")
    print("\033[1A", end="")
    print("\033[K", end="")
    reader, writer = await asyncio.open_connection(host, 8888)
    print(f"Connected to {host}!")

    private_key, mod = rsa_keygen(2048)

    print("\033[1A", end="")
    print("\033[K", end="")

    writer.write(mod.to_bytes((mod.bit_length() + 7) // 8, "little"))
    await writer.drain()

    key = await reader.read(16384)
    key = int.from_bytes(key, "little")
    key = rsa_encrypt(key, private_key, mod)
    key = key.to_bytes((key.bit_length() + 7) // 8, "little")

    encryption = Encryption(key)
    
    ip = writer.get_extra_info("peername")[0]
    print(f"Connected to {ip}!")
    await asyncio.gather(write(writer, encryption), read(reader, writer, encryption))


if __name__ == "__main__":
    try:
        host = input("Who would you like to connect to? ")
        print("\033[1A", end="")
        print("\033[K", end="")
        asyncio.run(client(host))
    except KeyboardInterrupt:
        raise SystemExit
