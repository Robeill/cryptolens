DEFAULT_WAREHOUSE = "main"


def total_stock(counts):
    total = 0
    for key in counts:
        total += counts[key]
    return total


def reindex(records, key="sku"):
    return {record[key]: record for record in records}


def merge(primary, secondary):
    merged = dict(primary)
    for key, value in secondary.items():
        if key not in merged:
            merged[key] = value
    return merged


def sort_by(records, key):
    return sorted(records, key=lambda record: record[key])
