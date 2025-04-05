import fitz  # PyMuPDF
import re
import pandas as pd

# Function to extract raw text from the PDF
def extract_text_blocks(pdf_path):
    """Extracts text blocks from the PDF for parsing."""
    blocks = []
    try:
        with fitz.open(pdf_path) as doc:
            for page in doc:
                blocks.extend(page.get_text("blocks"))
        return blocks
    except Exception as e:
        print(f"Error extracting text: {e}")
        return []

# Function to parse text blocks
def parse_pdf_blocks(blocks):
    """Parses text blocks to extract CVE details."""
    data = {
        "CVE ID": [],
        "Impact": [],
        "Description": [],
        "OEM Name": [],
        "Severity Level": [],
        "Mitigation": [],
        "Published Date": []
    }

    current_vendor = None
    current_product = None

    for block in blocks:
        text = block[4].strip()  # Extract the block's text content

        # Detect Vendor
        if text.startswith("Vendor:"):
            current_vendor = text.split("Vendor:")[1].strip()

        # Detect Product
        if text.startswith("Product:"):
            current_product = text.split("Product:")[1].strip()

        # Extract other fields when CVE ID is found
        if "CVE-" in text:
            cve_id = re.search(r"CVE-\d{4}-\d{4,7}", text)
            publish_date = re.search(r"(\d{2}-\w{3}-\d{4})", text)
            severity = re.search(r"CVSSv3\s*([\d.]+)", text)
            description = re.search(r"Improper.*?(CVE-\d{4}-\d{4,7})", text, re.DOTALL)
            mitigation = re.search(r"Patch\s*:\s*([\w\s/-]+)", text)
            patch_url = re.search(r"https?://[\w./-]+", text)
            impact = re.search(r"Weakness.*?:\s*(.*)", text)

            # Combine patch URL with mitigation if available
            mitigation_text = mitigation.group(1).strip() if mitigation else ""
            if patch_url:
                mitigation_text += f" {patch_url.group()}"

            # Append data to lists
            data["CVE ID"].append(cve_id.group() if cve_id else None)
            data["Impact"].append(impact.group(1).strip() if impact else None)
            data["Description"].append(description.group(0).strip() if description else None)
            data["OEM Name"].append(current_vendor)
            data["Severity Level"].append(severity.group(1) if severity else None)
            data["Mitigation"].append(mitigation_text if mitigation_text else None)
            data["Published Date"].append(publish_date.group(1) if publish_date else None)

    return data

# Function to save parsed data to a CSV file
def save_to_csv(data, output_file):
    """Saves the parsed data to a CSV file."""
    df = pd.DataFrame(data)
    df.to_csv(output_file, index=False)
    print(f"Data saved to {output_file}")

# Main function to process the PDF and save extracted data
def process_pdf(pdf_path, output_file):
    """Main function to process the PDF."""
    print("Extracting text blocks...")
    blocks = extract_text_blocks(pdf_path)

    print("Parsing text blocks...")
    parsed_data = parse_pdf_blocks(blocks)

    print("Saving parsed data...")
    save_to_csv(parsed_data, output_file)
    print("Process completed.")

# Example usage
if __name__ == "__main__":
    pdf_path = "C:/Users/dhana/Downloads/16_31_Oct24_CVE.pdf"
    output_csv = "NTRO_vulnerability.csv"
    process_pdf(pdf_path, output_csv)
