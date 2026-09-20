

def write(path: str, mode: str, payload: str) -> None:
    with open("data/" + path, mode, encoding="UTF-8") as f:
        f.write(payload)

def write_set(path: str, mode: str, payload: set[str]) -> None:
    joined = "\n".join(payload)
    write(path, mode, joined)