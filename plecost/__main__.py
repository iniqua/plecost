from plecost.cve_search import search_cves

def main():
    ret = search_cves("jetpack")

    for r in ret:
        print(r)


if __name__ == '__main__':
    main()
