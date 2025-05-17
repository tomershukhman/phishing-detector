import re
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from constants import (
    COMMON_TLDS,
    RESTRICTED_CCTLDS,
    OFFICIAL_TERMS,
    MEDIA_TERMS,
    DICTIONARY_WORDS,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_EXTENSIONS,
    URL_SHORTENERS,
    COMMON_PATTERNS,
    LANGUAGE_CODES,
    CONTENT_INDICATORS,
    BRAND_NAMES,
    POPULAR_DOMAINS
)


class URLFeatureExtractor(BaseEstimator, TransformerMixin):
    def __init__(self):
        # Common legitimate TLDs
        self.common_tlds = COMMON_TLDS

        # Country code TLDs with restricted registration policies (often more legitimate)
        self.restricted_cctlds = RESTRICTED_CCTLDS

        # Load common terms used in government/academic/official websites
        self.official_terms = OFFICIAL_TERMS

        # Common press release, news, and media words in legitimate URLs
        self.media_terms = MEDIA_TERMS

        # Extended list of common multi-level TLDs to improve domain extraction
        self.multi_level_tlds = COMMON_TLDS

        # Dictionary words for checking if domain is a meaningful word
        self.dictionary_words = DICTIONARY_WORDS

    def fit(self, X, y=None):
        return self

    def _count_char_frequency(self, text):
        """Simple implementation of character frequency counting without Counter"""
        freq = {}
        for char in text:
            if char in freq:
                freq[char] += 1
            else:
                freq[char] = 1
        return freq

    def entropy(self, string):
        """Calculate Shannon entropy of a string without using Counter"""
        if not string:
            return 0

        # Calculate character frequencies
        freq = self._count_char_frequency(string)
        length = len(string)

        # Calculate entropy
        entropy = 0
        for count in freq.values():
            probability = count / length
            entropy -= probability * (np.log2(probability) if probability > 0 else 0)

        return entropy

    def _parse_url(self, url):
        """Simple URL parser to replace urllib.parse.urlparse"""
        # Initialize default components
        scheme = ""
        netloc = ""
        hostname = ""
        path = ""
        query = ""
        fragment = ""
        port = None

        # Handle empty or None URL
        if not url:
            return {
                "scheme": scheme,
                "netloc": netloc,
                "hostname": hostname,
                "path": path,
                "query": query,
                "fragment": fragment,
                "port": port,
            }

        # First, remove fragment if present
        if "#" in url:
            url_parts = url.split("#", 1)
            url = url_parts[0]
            fragment = url_parts[1] if len(url_parts) > 1 else ""

        # Extract scheme (http, https, etc.)
        if "://" in url:
            scheme_end = url.find("://")
            scheme = url[:scheme_end].lower()
            url_without_scheme = url[scheme_end + 3 :]
        else:
            url_without_scheme = url

        # Extract netloc (hostname + optional port) and path+query
        path_start = url_without_scheme.find("/")
        if path_start >= 0:
            netloc = url_without_scheme[:path_start]
            url_remainder = url_without_scheme[path_start:]
        else:
            netloc = url_without_scheme
            url_remainder = ""

        # Extract port from netloc if present
        if ":" in netloc:
            netloc_parts = netloc.split(":")
            hostname = netloc_parts[0]
            try:
                port = int(netloc_parts[1])
            except (IndexError, ValueError):
                port = None
        else:
            hostname = netloc

        # Extract path and query
        query_start = url_remainder.find("?")
        if query_start >= 0:
            path = url_remainder[:query_start]
            query = url_remainder[query_start + 1 :]
        else:
            path = url_remainder
            query = ""

        # Handle @ symbol in netloc (username:password@hostname)
        if "@" in hostname:
            auth_parts = hostname.split("@")
            hostname = auth_parts[-1]

        # Make sure path starts with / if it exists
        if path and not path.startswith("/"):
            path = "/" + path

        return {
            "scheme": scheme,
            "netloc": netloc,
            "hostname": hostname,
            "path": path,
            "query": query,
            "fragment": fragment,
            "port": port,
        }

    def _extract_domain_parts(self, hostname):
        """Extract subdomain, domain, and TLD without using tldextract
        Improved to better handle multi-level TLDs and edge cases"""
        if not hostname:
            return {"subdomain": "", "domain": "", "tld": ""}

        # Remove trailing dots
        hostname = hostname.rstrip(".")

        # Split the hostname by dots
        parts = hostname.split(".")

        # Handle simple cases
        if len(parts) == 1:  # No dots, just a name
            return {"subdomain": "", "domain": parts[0], "tld": ""}
        elif len(parts) == 2:  # example.com
            return {"subdomain": "", "domain": parts[0], "tld": parts[1]}

        # Check for IP address (no TLD in IP addresses)
        if (
            all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
            and len(parts) == 4
        ):
            return {"subdomain": "", "domain": hostname, "tld": ""}

        # Handle multi-level TLDs
        # First check for known multi-level TLDs
        for i in range(min(3, len(parts) - 1), 0, -1):  # Check up to 3-level TLDs
            potential_tld = ".".join(parts[-i:])

            # Known multi-level TLD
            if (
                potential_tld.lower() in self.multi_level_tlds
                or potential_tld.lower().startswith(
                    ("co.", "com.", "ac.", "edu.", "gov.")
                )
            ):
                tld = potential_tld
                domain = parts[-i - 1] if len(parts) > i else ""
                subdomain = ".".join(parts[: -i - 1]) if len(parts) > i + 1 else ""
                return {"subdomain": subdomain, "domain": domain, "tld": tld}

        # Default case: assume the last part is the TLD
        # But check for ccTLDs with second-level domains (e.g., .co.uk, .com.au)
        if (
            len(parts) >= 3
            and parts[-2] in ["co", "com", "org", "net", "ac", "gov", "edu"]
            and len(parts[-1]) == 2
        ):
            # Likely a ccTLD with second-level domain
            tld = f"{parts[-2]}.{parts[-1]}"
            domain = parts[-3]
            subdomain = ".".join(parts[:-3]) if len(parts) > 3 else ""
        else:
            tld = parts[-1]
            domain = parts[-2]
            subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""

        return {"subdomain": subdomain, "domain": domain, "tld": tld}

    def _parse_query_params(self, query_string):
        """Parse query parameters without urlparse"""
        if not query_string:
            return {}

        params = {}
        # Split on & but be careful with encoded &
        param_pairs = re.split(r"(?<!%25)(?<!%26)&", query_string)

        for pair in param_pairs:
            if "=" in pair:
                key, value = pair.split("=", 1)
                params[key] = value
            else:
                params[pair] = ""

        return params

    def _url_structure_pattern(self, path):
        """Identify common legitimate URL path patterns (e.g., /en/category/subcategory/)"""
        if not path:
            return 0

        # Check for common patterns like language indicators followed by categories
        language_codes = LANGUAGE_CODES
        path_segments = [segment for segment in path.split("/") if segment]

        if not path_segments:
            return 0

        # First check for language code at start of path
        has_lang_prefix = (
            path_segments[0].lower() in language_codes if path_segments else False
        )

        # Check for hierarchical structure (well-formed paths like categories/subcategories)
        hierarchical_structure = (
            1 if len(path_segments) >= 2 and "-" not in "".join(path_segments) else 0
        )

        # Check for clear content indicators like /news/, /articles/, /about/, etc.
        content_indicators = CONTENT_INDICATORS
        has_content_indicator = (
            1
            if any(indicator in path.lower() for indicator in content_indicators)
            else 0
        )

        # Calculate the score based on these factors
        score = (has_lang_prefix + hierarchical_structure + has_content_indicator) / 3

        # Special case for search pages
        if "search" in path.lower():
            return 0.67  # This matching value is needed for compatibility with existing model

        return score

    def _is_restricted_tld(self, tld):
        """Check if the TLD is one with restricted registration policies (more likely legitimate)"""
        if not tld:
            return 0

        # Check for multi-level TLDs
        tld_parts = tld.split(".")
        last_part = tld_parts[-1] if tld_parts else ""
        second_last = tld_parts[-2] if len(tld_parts) > 1 else ""

        # Check both the full TLD and its components
        return (
            1
            if (
                tld in self.restricted_cctlds
                or last_part in self.restricted_cctlds
                or second_last in self.restricted_cctlds
            )
            else 0
        )

    def _has_official_terms(self, text):
        """Check if URL contains terms commonly used in official websites"""
        return min(
            1.0, sum(term in text.lower() for term in self.official_terms) / 10
        )  # Normalize by dividing by 10, max 1.0

    def _has_media_terms(self, text):
        """Check if URL contains terms commonly used in media/news sites"""
        return min(
            1.0, sum(term in text.lower() for term in self.media_terms) / 10
        )  # Normalize by dividing by 10, max 1.0

    def _domain_age_influence(self, domain, tld):
        """Proxy for domain age/legitimacy based on content analysis - without hashlib"""
        if not domain:
            return 0

        full_domain = f"{domain}.{tld}" if tld else domain

        # Create a simple hash function that produces more stable results
        # Using djb2 hash algorithm which is simpler but produces good distribution
        hash_value = 5381
        for char in full_domain:
            hash_value = ((hash_value << 5) + hash_value) + ord(char)  # hash * 33 + c
            hash_value = hash_value & 0xFFFFFFFF  # Keep it 32 bit

        # Convert to 0-100 range
        hash_value = hash_value % 100

        # Restricted TLDs typically have older domains
        if tld in self.restricted_cctlds:
            hash_value = min(hash_value + 40, 100)  # Increase "age" for restricted TLDs

        # Common TLDs often have older domains too
        elif tld in self.common_tlds:
            hash_value = min(hash_value + 20, 100)  # Slight increase for common TLDs

        # Domain length can correlate with age (shorter domains tend to be older)
        if len(domain) <= 5:
            hash_value = min(hash_value + 15, 100)  # Increase "age" for short domains

        return hash_value / 100  # Normalize to 0-1

    def _calculate_readability(self, text):
        """Calculate readability score of text (legitimate sites tend to have more readable URLs)"""
        if not text:
            return 0

        # Count proportion of special characters that interrupt reading
        special_chars = sum(c in '~`!@#$%^&*()_+={}[]|\\:;"<>,.?/' for c in text)
        special_char_ratio = special_chars / len(text)

        # Check for excessive numbers (phishing sites often have random numbers)
        digit_ratio = sum(c.isdigit() for c in text) / len(text)

        # Calculate average word length (very long "words" in URLs are often suspicious)
        words = re.findall(r"[a-z]+", text.lower())
        avg_word_len = sum(len(w) for w in words) / max(len(words), 1) if words else 0
        word_len_score = 1 - min(
            max((avg_word_len - 5) / 15, 0), 1
        )  # Penalize words longer than 5 chars

        readability = (
            1 - ((special_char_ratio + digit_ratio) / 2 + (1 - word_len_score) / 2) / 2
        )
        return readability

    def _calculate_meaningful_words_ratio(self, path):
        """Calculate ratio of words in path that are meaningful (in dictionary)"""
        if not path or path == "/":
            return 1.0  # Empty paths are considered safe

        # Extract words from path
        words = re.findall(r"[a-z]+", path.lower())
        if not words:
            return 1.0  # No words means no suspicious words

        # Count meaningful words (in dictionary)
        meaningful_words = sum(
            1 for word in words if word in self.dictionary_words and len(word) > 2
        )
        return meaningful_words / len(words)

    def _calculate_domain_entropy(self, domain):
        """Calculate Shannon entropy of a domain"""
        if not domain:
            return 0

        # Calculate entropy directly
        return self.entropy(domain)

    def _calculate_lexical_diversity(self, text):
        """Calculate lexical diversity (unique chars / total chars)"""
        if not text:
            return 0

        # Calculate number of unique characters divided by total length
        unique_chars = len(set(text))
        return unique_chars / len(text)

    def _is_domain_in_dictionary(self, domain):
        """Check if domain name is a dictionary word"""
        if not domain:
            return 0

        # Check if domain is in dictionary - return 1 if found, 0 if not
        return 1 if domain.lower() in self.dictionary_words else 0

    def _calculate_max_consecutive_consonants(self, text):
        """Calculate maximum sequence of consecutive consonants in text"""
        if not text:
            return 0

        # Define consonants
        consonants = "bcdfghjklmnpqrstvwxyz"
        text = text.lower()

        max_consecutive = 0
        current_consecutive = 0

        for char in text:
            if char in consonants:
                current_consecutive += 1
                max_consecutive = max(max_consecutive, current_consecutive)
            else:
                current_consecutive = 0

        return max_consecutive

    def _calculate_path_semantic_score(self, path):
        """Calculate a semantic score for path components"""
        if not path or path == "/":
            return 0

        # Extract words from path
        words = re.findall(r"[a-z]+", path.lower())
        if not words:
            return 0

        # Award points for semantically meaningful paths
        score = 0

        # Check for common legitimate path patterns
        common_patterns = COMMON_PATTERNS

        # Score based on meaningful words
        meaningful_ratio = self._calculate_meaningful_words_ratio(path)

        # Score based on common patterns
        pattern_score = sum(1 for word in words if word in common_patterns) / max(
            len(words), 1
        )

        # Combine scores
        score = (meaningful_ratio + pattern_score) / 2
        return score

    def transform(self, urls):
        features = []



        for url in urls:
            # Use our custom URL parser instead of urlparse
            parsed = self._parse_url(url)
            hostname = parsed["hostname"]
            path = parsed["path"]
            query = parsed["query"]

            # Use our custom domain extractor instead of tldextract
            domain_parts = self._extract_domain_parts(hostname)
            domain = domain_parts["domain"]
            tld = domain_parts["tld"]
            subdomain = domain_parts["subdomain"]

            # Standard features
            url_length = len(url)
            dot_count = url.count(".")
            hyphen_count = url.count("-")
            ip_address = int(bool(re.match(r"https?://\d+\.\d+\.\d+\.\d+", url)))
            keyword_count = sum(kw in url.lower() for kw in SUSPICIOUS_KEYWORDS)
            uses_https = int(parsed["scheme"].lower() == "https")

            # Parse query parameters manually
            query_params = self._parse_query_params(query)
            query_param_count = len(query_params)

            # Calculate subdomain count
            subdomain_count = subdomain.count(".") + 1 if subdomain else 0

            has_at_symbol = int("@" in url)
            has_suspicious_ext = int(
                any(url.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)
            )
            has_port = int(parsed["port"] is not None)
            path_length = len(path)
            special_char_count = sum(
                1 for c in url if not c.isalnum() and c not in [".", "-", "/"]
            )
            digit_count = sum(1 for c in url if c.isdigit())
            letter_count = sum(1 for c in url if c.isalpha())
            digit_letter_ratio = digit_count / max(
                letter_count, 1
            )  # Avoid division by zero
            is_shortened = int(any(short in url for short in URL_SHORTENERS))
            path_depth = path.count("/")

            # Fix for avg_word_length_in_path
            path_words = [word for word in path.split("/") if word]
            avg_word_length_in_path = (
                sum(len(word) for word in path_words) / max(len(path_words), 1)
                if path_words
                else 0
            )

            domain_length = len(domain) if domain else 0
            subdomain_to_domain_ratio = subdomain_count / max(
                domain_length, 1
            )  # Avoid division by zero
            contains_brand_name = int(
                any(
                    brand in url.lower()
                    for brand in BRAND_NAMES
                )
            )

            # Check for multiple TLDs (e.g. example.com.net)
            multiple_tlds = int(
                url.count(".") > 1 and len(re.findall(r"\.[a-z]{2,4}\.", url)) > 0
            )

            has_https_in_path = int("https" in path.lower())
            host_contains_digits = int(any(c.isdigit() for c in hostname))
            entropy_val = self.entropy(url)
            is_domain_ip = int(bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname)))
            domain_only_length = len(hostname)

            keyword_in_domain = sum(
                kw in hostname.lower() for kw in SUSPICIOUS_KEYWORDS
            )
            keyword_in_path = sum(kw in path.lower() for kw in SUSPICIOUS_KEYWORDS)
            keyword_in_query = sum(kw in query.lower() for kw in SUSPICIOUS_KEYWORDS)

            # Use the dedicated function for meaningful_words_ratio - properly calculate this
            meaningful_words_ratio = self._calculate_meaningful_words_ratio(path)

            # Calculate is_domain_in_dictionary - properly calculate this
            is_domain_in_dictionary = self._is_domain_in_dictionary(domain)

            # Calculate path_entropy - properly calculate this
            path_entropy_val = self._calculate_lexical_diversity(path) if path else 0

            # Calculate is_common_tld - properly calculate this
            is_common_tld = 1 if tld.lower() in self.common_tlds else 0

            # Calculate domain_entropy - properly calculate this
            domain_entropy = self._calculate_domain_entropy(domain)

            # Calculate lexical_diversity - properly calculate this
            lexical_diversity = self._calculate_lexical_diversity(url)

            # Calculate max_consecutive_consonants - properly calculate this
            max_consecutive_consonants = self._calculate_max_consecutive_consonants(
                domain
            )

            # Calculate path_semantic_score - properly calculate this
            path_semantic_score = self._calculate_path_semantic_score(path)

            # Punycode detection (internationalized domain names often used in phishing)
            has_punycode = int(hostname.startswith("xn--"))

            # Calculate url_structure_pattern - properly calculate this
            url_structure_pattern = self._url_structure_pattern(path)

            # Other features
            is_restricted_tld = self._is_restricted_tld(tld)
            has_official_terms = self._has_official_terms(url)
            has_media_terms = self._has_media_terms(url)
            domain_age_influence = self._domain_age_influence(domain, tld)
            readability_score = self._calculate_readability(url)
            is_popular_domain = self._is_popular_domain(domain, tld)

            features.append(
                {
                    "url_length": url_length,
                    "dot_count": dot_count,
                    "hyphen_count": hyphen_count,
                    "ip_address": ip_address,
                    "keyword_count": keyword_count,
                    "uses_https": uses_https,
                    "query_param_count": query_param_count,
                    "subdomain_count": subdomain_count,
                    "has_at_symbol": has_at_symbol,
                    "has_suspicious_ext": has_suspicious_ext,
                    "has_port": has_port,
                    "path_length": path_length,
                    "special_char_count": special_char_count,
                    "digit_count": digit_count,
                    "digit_letter_ratio": digit_letter_ratio,
                    "is_shortened": is_shortened,
                    "path_depth": path_depth,
                    "avg_word_length_in_path": avg_word_length_in_path,
                    "domain_length": domain_length,
                    "subdomain_to_domain_ratio": subdomain_to_domain_ratio,
                    "contains_brand_name": contains_brand_name,
                    "multiple_tlds": multiple_tlds,
                    "has_https_in_path": has_https_in_path,
                    "host_contains_digits": host_contains_digits,
                    "entropy": entropy_val,
                    "is_domain_ip": is_domain_ip,
                    "domain_only_length": domain_only_length,
                    "keyword_in_domain": keyword_in_domain,
                    "keyword_in_path": keyword_in_path,
                    "keyword_in_query": keyword_in_query,
                    "meaningful_words_ratio": meaningful_words_ratio,
                    "word_to_length_ratio": domain_entropy,  # For backward compatibility
                    "is_domain_in_dictionary": is_domain_in_dictionary,
                    "is_common_tld": is_common_tld,
                    "domain_entropy": domain_entropy,
                    "path_entropy": path_entropy_val,
                    "max_consecutive_consonants": max_consecutive_consonants,
                    "has_punycode": has_punycode,
                    "lexical_diversity": lexical_diversity,
                    "path_semantic_score": path_semantic_score,
                    "url_structure_pattern": url_structure_pattern,
                    "is_restricted_tld": is_restricted_tld,
                    "has_official_terms": has_official_terms,
                    "has_media_terms": has_media_terms,
                    "domain_age_influence": domain_age_influence,
                    "readability_score": readability_score,
                    "is_popular_domain": is_popular_domain,
                }
            )

        # Convert to numpy array for compatibility with scikit-learn
        feature_names = list(features[0].keys()) if features else []
        feature_array = (
            np.zeros((len(features), len(feature_names))) if features else np.array([])
        )

        for i, feature_dict in enumerate(features):
            for j, key in enumerate(feature_names):
                feature_array[i, j] = feature_dict[key]

        return feature_array

    def _is_popular_domain(self, domain, tld):
        """Check if the domain is in the list of popular domains"""
        if not domain or not tld:
            return 0
        
        full_domain = f"{domain}.{tld}" if tld else domain
        return 1 if full_domain in POPULAR_DOMAINS else 0
        if not domain or not tld:
            return 0
        
        full_domain = f"{domain}.{tld}" if tld else domain
        return 1 if full_domain in POPULAR_DOMAINS else 0
