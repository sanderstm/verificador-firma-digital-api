from fastapi import FastAPI
from typing import Optional
from typing import Union
import uvicorn
from api_src.certificate import process_base_64_pdf


pdf_check = FastAPI()

from pydantic import BaseModel

class Pdf_model(BaseModel):
    
    name: Optional[str] = None
    base64_pdf: str

@pdf_check.get("/")
async def root():  
    return {"message": "Hello World"}

@pdf_check.get("/check")
async def check():
    return {"message":"ok"}

@pdf_check.post("/api/validar-pdf")
async def validar(pdf: Pdf_model):
    # print(pdf)
    return process_base_64_pdf(pdf.base64_pdf)




if __name__ == "__main__":
    uvicorn.run(
        "main:pdf_check",
        host="localhost",
        port=8008,
        log_level="debug",
        reload=True,
    )
