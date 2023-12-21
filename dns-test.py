import whois
import dns.resolver


for str in [
    '1v1.lol',
    'fr',
    'pascal-aubry2.fr',
    'ac-rennes.fr',
    'www.ac-rennes.fr',
    'u-bordeaux2.fr',
    'u-psud.fr',
    'ip-stresser-xbox.hdxba.com.',
    'ddlddl.free.fr',
]:
    print(f'{str}')
    domain_parts = str.split('.')
    domain = '.'.join(domain_parts[-2:])
    print(f'  domain = {domain}')
    # whois_domain = whois.whois(domain)["domain_name"]
    whois_domain = whois.whois(domain)
    whois_domain_name = whois_domain["domain_name"]
    print(f'  WHOIS({domain}) = {whois_domain_name}')
    if whois_domain_name is None:
        continue
    try:
        print(f'  DNS({str}) = {", ".join([ipval.to_text() for ipval in dns.resolver.query(str, "A")])}')
    except dns.resolver.NoAnswer:
        continue
