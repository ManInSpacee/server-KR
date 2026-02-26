# main.py
from fastapi import FastAPI

app = FastAPI()


@app.get("/")
async def root():
    return {"message": "Hello MIREA!"}

@app.get("/custom")
async def root():
    return {"message": "This is a custom message!"}
