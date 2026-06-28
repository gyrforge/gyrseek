import re

fixed_ids = ["29", "34", "40", "50", "75", "76", "77"]

def move_summaries():
    open_lines = []
    fixed_summaries = []
    
    with open("docs/OPEN_FINDINGS.md", "r") as f:
        lines = f.readlines()
        
    for line in lines:
        m = re.match(r'\|\s*(\w+)\s*\|', line)
        if m and m.group(1) in fixed_ids:
            line = line.replace("⚠️ Open", "✅ Fixed")
            fixed_summaries.append(line)
        else:
            open_lines.append(line)
            
    with open("docs/OPEN_FINDINGS.md", "w") as f:
        f.writelines(open_lines)
        
    with open("docs/FIXED_FINDINGS.md", "r") as f:
        fixed_lines = f.readlines()
        
    # Insert before the first --- or at the end of the table
    insert_idx = -1
    for i, line in enumerate(fixed_lines):
        if line.startswith("---") or (i > 0 and fixed_lines[i-1].startswith("|") and not line.startswith("|")):
            # Found end of table
            if line.startswith("---"):
                insert_idx = i
            else:
                insert_idx = i
            break
            
    if insert_idx == -1:
        insert_idx = len(fixed_lines)
        
    fixed_lines = fixed_lines[:insert_idx] + fixed_summaries + fixed_lines[insert_idx:]
    
    with open("docs/FIXED_FINDINGS.md", "w") as f:
        f.writelines(fixed_lines)


def move_details():
    with open("docs/OPEN_FINDINGS_DETAILED.md", "r") as f:
        content = f.read()
        
    open_details = []
    fixed_details = []
    
    blocks = re.split(r'(?=\n### Finding )', content)
    
    for block in blocks:
        if not block.strip():
            continue
            
        m = re.search(r'### Finding (\w+)', block)
        if m and m.group(1) in fixed_ids:
            # Change ⚠️ Open to ✅ Fixed
            block = block.replace("⚠️ Open", "✅ Fixed")
            # If there is no Root cause, we might need to adapt it, but let's just move it directly.
            # Usually FIXED_FINDINGS.md has "Fix:" or similar, but the user just wants them moved.
            fixed_details.append(block)
        else:
            open_details.append(block)
            
    with open("docs/OPEN_FINDINGS_DETAILED.md", "w") as f:
        f.write("".join(open_details))
        
    with open("docs/FIXED_FINDINGS_DETAILED.md", "a") as f:
        for block in fixed_details:
            f.write("\n---\n")
            f.write(block)

move_summaries()
move_details()
print("Findings moved successfully.")
