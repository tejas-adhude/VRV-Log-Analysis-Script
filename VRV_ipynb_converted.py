import pandas as pd

## Function to extract the data from line of log file
def extract_info(line):
    try:
        line_split= line.split()
        ip = line_split[0]
        datetime = line.split("[")[1].split("]")[0]
        method, url, version = line.split('"')[1].split(" ")
        if line_split[-1].isnumeric():
            size = line_split[-1]
            status = line_split[-2]
            extra_info = None
        else:
            extra_info = line_split[-2].split('"')[1]+" "+line_split[-1].split('"')[0]
            size = line_split[-3]
            status = line_split[-4]

        data = {
            "IP Address": ip,
            "datetime": datetime,
            "method": method,
            "url": url,
            "version": version,
            "status": status,
            "size": size,
            "extra_info": extra_info
        }
        return data
    except Exception as e:
        print(f"Error parsing line: {line}\n{e}")
        return None

## Function to create the generator of extraced data from each line in log file
def perform_data_extraction(file_path,extract_info):
    try:
        with open(file_path, 'r') as log_file:
            for line in log_file:
                yield extract_info(line)
    except FileNotFoundError:
        print("File not found.")

## Function to count request per ip
def count_requests(data_df):
    # using group by and aggregation to count request per id
    ip_request_count = data_df.groupby('IP Address').size().reset_index(name='Request Count')
    ip_request_count.sort_values(by='Request Count', ascending=False, inplace=True)

    # output for request per id
    ip_request_count.to_csv("Requests per IP.csv",index=False)
    print("Requests Per Ip:")
    print(ip_request_count)

## Function to find most access endpoint
def most_access_endpoint(data_df):
    url_request_count = data_df.groupby('url').size().reset_index(name='Request Count')
    most_accessed_url = url_request_count.sort_values(by='Request Count', ascending=False).iloc[0]

    # output for
    df = pd.DataFrame({
        "Endpoint":[most_accessed_url['url']],
        "Access Count":[most_accessed_url['Request Count']]
        })
    df.to_csv("Most Accessed Endpoint.csv",index=False)

    print("Most Frequently Accessed Endpoint:")
    print(df)

## Function to count the suspicious activity
def detect_suspicious(data_df,threshold=10):
    failed_logins = data_df[(data_df['status'] == 401) | (data_df['extra_info'] == 'Invalid credentials')]
    failed_login_counts = failed_logins.groupby('IP Address').size().reset_index(name='Failed Login Attempts')

    # Filter by threshold
    flagged_ips = failed_login_counts[failed_login_counts['Failed Login Attempts'] > threshold]

    flagged_ips.sort_values(by='Failed Login Attempts', ascending=False, inplace=True)

    if not flagged_ips.empty:
        print("Suspicious Activity Detected:")
        print(flagged_ips)
        flagged_ips.to_csv("Suspicious Activity.csv",index=False)
    else:
        print("No Suspicious Activity Detected.")

## File path
file_path="sample.log"

## convert the log data, into pandas df , with tokens
extracted_data = perform_data_extraction(file_path,extract_info)
extracted_df = pd.DataFrame(extracted_data)

## Request per ip
count_requests(extracted_df)
print(".............................................................................")

## Most frquently access endpoint
most_access_endpoint(extracted_df)
print(".............................................................................")

## Detect Suspicious Activity
# using threshold = 0
detect_suspicious(extracted_df,threshold=0)