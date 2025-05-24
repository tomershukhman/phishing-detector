#!/usr/bin/env python3
"""
FastAPI server to receive performance data from the phishing detector Chrome extension.
This server listens on http://127.0.0.1:6543/verdict and logs the received data.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Phishing Detector Performance Server",
    description="Receives performance data from the Chrome extension",
    version="1.0.0"
)

# Add CORS middleware to allow requests from Chrome extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify the extension origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic model for the expected data structure
class PerformanceData(BaseModel):
    url: str
    groupId: int
    isPhishing: bool
    responseTimeMs: float
    heapChangeBytes: int

# Store received data (in production, you'd use a database)
received_data = []

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "message": "Phishing Detector Performance Server is running",
        "timestamp": datetime.now().isoformat(),
        "received_count": len(received_data)
    }

@app.post("/verdict")
async def receive_verdict(data: PerformanceData):
    """
    Receive performance data from the Chrome extension
    """
    try:
        # Log the received data
        logger.info(f"Received performance data: {data.model_dump()}")
        
        # Add timestamp and store the data
        data_with_timestamp = {
            **data.model_dump(),
            "received_at": datetime.now().isoformat()
        }
        received_data.append(data_with_timestamp)
        
        # Pretty print for console visibility
        print("\n" + "="*60)
        print("📊 NEW PERFORMANCE DATA RECEIVED")
        print("="*60)
        print(f"🌐 URL: {data.url}")
        print(f"📊 Group ID: {data.groupId}")
        print(f"🚨 Is Phishing: {data.isPhishing}")
        print(f"⏱️  Response Time: {data.responseTimeMs}ms")
        print(f"💾 Heap Change: {data.heapChangeBytes} bytes")
        print(f"🕐 Received At: {data_with_timestamp['received_at']}")
        print("="*60 + "\n")
        
        return {
            "status": "success",
            "message": "Performance data received successfully",
            "received_at": data_with_timestamp["received_at"],
            "data_id": len(received_data)
        }
        
    except Exception as e:
        logger.error(f"Error processing performance data: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error processing data: {str(e)}")

@app.get("/data")
async def get_all_data():
    """
    Get all received performance data
    """
    return {
        "count": len(received_data),
        "data": received_data
    }

@app.get("/data/latest")
async def get_latest_data():
    """
    Get the most recently received performance data
    """
    if not received_data:
        return {"message": "No data received yet"}
    
    return {
        "latest": received_data[-1],
        "total_count": len(received_data)
    }

@app.get("/stats")
async def get_stats():
    """
    Get statistics about the received data
    """
    if not received_data:
        return {"message": "No data received yet"}
    
    phishing_count = sum(1 for item in received_data if item["isPhishing"])
    safe_count = len(received_data) - phishing_count
    
    response_times = [item["responseTimeMs"] for item in received_data]
    avg_response_time = sum(response_times) / len(response_times) if response_times else 0
    
    heap_changes = [item["heapChangeBytes"] for item in received_data]
    avg_heap_change = sum(heap_changes) / len(heap_changes) if heap_changes else 0
    
    return {
        "total_requests": len(received_data),
        "phishing_detected": phishing_count,
        "safe_sites": safe_count,
        "avg_response_time_ms": round(avg_response_time, 2),
        "avg_heap_change_bytes": round(avg_heap_change, 2),
        "latest_request": received_data[-1]["received_at"] if received_data else None
    }

@app.delete("/data")
async def clear_data():
    """
    Clear all received data
    """
    global received_data
    count = len(received_data)
    received_data = []
    return {
        "message": f"Cleared {count} data entries",
        "remaining_count": len(received_data)
    }

if __name__ == "__main__":
    print("\n🚀 Starting Phishing Detector Performance Server")
    print("📡 Listening for Chrome extension data on http://127.0.0.1:6543")
    print("📊 Endpoint: POST /verdict")
    print("🌐 Web interface: http://127.0.0.1:6543")
    print("📈 Stats: http://127.0.0.1:6543/stats")
    print("💾 All data: http://127.0.0.1:6543/data")
    print("\nPress Ctrl+C to stop the server\n")
    
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=6543,
        log_level="info"
    )
