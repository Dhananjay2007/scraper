from pytesseract import image_to_string
from pdf2image import convert_from_path
import os

# Path to Tesseract OCR executable (update this if needed)
# On Windows, specify the full path, e.g., 'C:\\Program Files\\Tesseract-OCR\\tesseract.exe'
TESSERACT_CMD = r'C:\Users\dhana\Downloads\tesseract-main\tesseract-main\tesseract.exe'

# Input PDF file
INPUT_PDF = "C:/Users/dhana/Downloads/16_31_Oct24_CVE.pdf"  # Replace with your PDF file
OUTPUT_TEXT_FILE = 'extracted_text.txt'

# Tesseract configuration
from pytesseract import pytesseract

pytesseract.tesseract_cmd = TESSERACT_CMD


def pdf_to_text(pdf_path, output_file):
    try:
        # Convert PDF to images (one image per page)
        print(f"Converting PDF to images...")
        pages = convert_from_path(pdf_path, dpi=300)

        # Prepare to save extracted text
        all_text = []

        # Process each page image with Tesseract OCR
        for i, page in enumerate(pages):
            print(f"Processing page {i + 1}...")
            text = image_to_string(page)
            all_text.append(text)

        # Save extracted text to the output file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(all_text))

        print(f"Text extraction complete. Extracted text saved to {output_file}")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    # Run the function
    pdf_to_text(INPUT_PDF, OUTPUT_TEXT_FILE)
