def generate_report(data):

    with open("report.txt", "w") as f:
        for line in data:
            f.write(line + "\n")