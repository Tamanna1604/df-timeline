import os

file_path = r"C:/Users/karan/OneDrive/Desktop/Cyber_techniques Project/templates/report_template.html"
print(f"Attempting to open file at: {file_path}")

if not os.path.exists(file_path):
    
    print(f"Error: The file at {file_path} does not exist!")
else:
    with open(file_path, "rb") as file:
        print(f"Successfully opened {file_path}")
