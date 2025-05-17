#!/usr/bin/env python3
"""
Export trained models to JSON format for use in a Chrome extension.
"""
import json
import numpy as np
from joblib import load
import os
from feature_extractor import URLFeatureExtractor
from constants import SUSPICIOUS_KEYWORDS, SUSPICIOUS_EXTENSIONS, URL_SHORTENERS, BRAND_NAMES, COMMON_PATTERNS, LANGUAGE_CODES, CONTENT_INDICATORS, POPULAR_DOMAINS

# Custom JSON encoder to handle numpy types
class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        return super(NumpyEncoder, self).default(obj)

# Initialize the feature extractor to get access to its constants
feature_extractor = URLFeatureExtractor()

# Load the saved models and preprocessors
print("[+] Loading models and preprocessors...")
svm_model = load('models/svm_model.joblib')
feature_selector = load('models/feature_selector.joblib')
custom_extractor = load('models/custom_extractor.joblib')

# Load the selected features information
print("[+] Loading selected features...")
with open('models/selected_features.json', 'r') as f:
    selected_features = json.load(f)
    rfe_features = selected_features.get('rfe_selected', [])

# Extract SVM model parameters
print("[+] Extracting SVM parameters...")
model_data = {
    'intercept': svm_model.intercept_[0],
    'coefficients': svm_model.coef_[0],
    'classes': svm_model.classes_.tolist()
}

# Get feature names and constants from the feature extractor
print("[+] Extracting feature extractor constants...")
constants = {
    'commonTlds': list(feature_extractor.common_tlds),
    'restrictedTlds': list(feature_extractor.restricted_cctlds),
    'officialTerms': list(feature_extractor.official_terms),
    'mediaTerms': list(feature_extractor.media_terms),
    'multiLevelTlds': list(feature_extractor.multi_level_tlds),
    'dictionaryWords': list(feature_extractor.dictionary_words),
    'suspiciousKeywords': list(SUSPICIOUS_KEYWORDS),
    'suspiciousExtensions': list(SUSPICIOUS_EXTENSIONS),
    'urlShorteners': list(URL_SHORTENERS),
    'brandNames': list(BRAND_NAMES),
    'commonPatterns': list(COMMON_PATTERNS),
    'languageCodes': list(LANGUAGE_CODES),
    'contentIndicators': list(CONTENT_INDICATORS),
    'popularDomains': list(POPULAR_DOMAINS)
}

# Save feature metadata and model data
print(f"[+] Feature count: {len(rfe_features)}")


model_data.update({
    'feature_names': rfe_features,
    'selected_features': rfe_features,
    'constants': constants
})

# Save model metadata as JSON
print("[+] Saving model metadata...")
extension_output_path = '../phishing-detector-extension/model_metadata.json'
with open(extension_output_path, 'w') as f:
    json.dump(model_data, f, cls=NumpyEncoder, indent=4)

print("[+] Export complete!")
print("[+] Output file:")
print(f"    - {extension_output_path} - Complete model data for the extension")
