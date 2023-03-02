def response(data, code, status, message):
    ready_data = list(data) if type(data) == list else data
    return {
        "status": status,
        "message": message,
        "code": code,
        "data": {
            "response": ready_data
        }
    }
