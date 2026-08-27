import typer

app = typer.Typer()
@app.command()
def version():
    print("cryptolens 0.1.0")

@app.command()
def scan(path: str = "."):
    print(f"scanning {path} (not implemented yet)")

if __name__ == "__main__":
    app()