"""Entry point: python -m hacking_mcp"""

from hacking_mcp.server import create_server


def main():
    server = create_server()
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
