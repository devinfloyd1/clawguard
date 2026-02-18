"""
Text Formatter - A completely safe skill that just formats text.
"""

def format_text(text: str, style: str = "bold") -> str:
    """Format text with the specified style."""
    if style == "bold":
        return f"**{text}**"
    elif style == "italic":
        return f"*{text}*"
    elif style == "code":
        return f"`{text}`"
    elif style == "upper":
        return text.upper()
    elif style == "lower":
        return text.lower()
    return text


def main():
    """Example usage."""
    print(format_text("Hello, World!", "bold"))
    print(format_text("Hello, World!", "italic"))


if __name__ == "__main__":
    main()
