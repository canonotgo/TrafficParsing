-i https://pypi.tuna.tsinghua.edu.cn/simple


```python
def hex_to_utf8(hex_value):
    # Convert hex string to bytes
    bytes_value = bytes.fromhex(hex_value)
    # Decode bytes to UTF-8 string
    utf8_string = bytes_value.decode('utf-8', errors='ignore')  # Use 'ignore' to handle any non-UTF-8 bytes gracefully
    return utf8_string

# Example usage
hex_value = '777777777777777777'
utf8_string = hex_to_utf8(hex_value)
print(f"UTF-8 String: {utf8_string}")
```
