def format_text(text, preserve_format=False):
    if preserve_format:
        return text
    return ''.join(filter(str.isalpha, text)).upper()

print(enumerate(format_text("Hello, world!", True)))