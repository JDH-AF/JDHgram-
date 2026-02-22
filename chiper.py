import base64

def process_text(text, key):
    """Шифрует/расшифровывает текст методом XOR с ключом"""
    if not key: return text
    # Зацикливаем ключ
    key_cycle = (key * (len(text) // len(key) + 1))[:len(text)]
    # XOR операция
    result = "".join(chr(ord(t) ^ ord(k)) for t, k in zip(text, key_cycle))
    return result

def encrypt_message(text, room_code):
    """Текст -> XOR -> Base64"""
    raw_cipher = process_text(text, room_code)
    return base64.b64encode(raw_cipher.encode()).decode()

def decrypt_message(encoded_text, room_code):
    """Base64 -> XOR -> Текст"""
    try:
        raw_cipher = base64.b64decode(encoded_text.encode()).decode()
        return process_text(raw_cipher, room_code)
    except Exception:
        return "[Ошибка расшифровки]"
      
