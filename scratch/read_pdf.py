import fitz  # PyMuPDF

pdf_path = "c:\\Users\\heman\\Downloads\\VulnerX\\vulnrisk_report.pdf"
print("Reading", pdf_path)
try:
    doc = fitz.open(pdf_path)
    for page_num, page in enumerate(doc):
        print(f"--- Page {page_num + 1} ---")
        print(page.get_text())
except Exception as e:
    print("Error:", e)
