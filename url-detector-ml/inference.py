#!/usr/bin/env python3
"""
URL Phishing Prediction Script

This script loads the trained model and feature extractors to
predict whether a given URL is malicious or benign. It shows
detailed information about the features and their impact on
the prediction.
"""

import argparse
import json
import numpy as np
from joblib import load
import os
import sys
from pathlib import Path
import pandas as pd
from feature_extractor import URLFeatureExtractor

class URLPredictor:
    """Class for predicting if a URL is phishing or benign"""
    
    def __init__(self):
        """Load the model, feature extractor, and feature selector"""
        # Define the paths to model files
        models_dir = Path('models')
        self.model_path = models_dir / 'svm_model.joblib'
        self.feature_extractor_path = models_dir / 'custom_extractor.joblib'
        self.feature_selector_path = models_dir / 'feature_selector.joblib'
        self.selected_features_path = models_dir / 'selected_features.json'
        
        # Check if all required files exist
        for path in [self.model_path, self.feature_extractor_path, 
                    self.feature_selector_path, self.selected_features_path]:
            if not path.exists():
                raise FileNotFoundError(f"Required file {path} not found. Have you trained the model?")
                
        # Load the trained model and preprocessing components
        print(f"[+] Loading model from {self.model_path}")
        self.model = load(self.model_path)
        
        print(f"[+] Loading feature extractor")
        self.feature_extractor = load(self.feature_extractor_path)
        
        print(f"[+] Loading feature selector")
        self.feature_selector = load(self.feature_selector_path)
        
        # Load the selected features list
        print(f"[+] Loading selected features list")
        with open(self.selected_features_path, 'r') as f:
            selected_features_data = json.load(f)
            # Use the RFE selected features as these are what the model was trained on
            self.selected_features = selected_features_data['rfe_selected']
            
        print(f"[+] Model loaded successfully with {len(self.selected_features)} features")
    
    def extract_features(self, url):
        """Extract features from a URL"""
        # Extract all features using the feature extractor
        X_features = self.feature_extractor.transform([url])
        
        # Convert to DataFrame with proper column names (all features)
        all_feature_names = [
            'url_length', 'dot_count', 'hyphen_count', 'ip_address',
            'keyword_count', 'uses_https', 'query_param_count',
            'subdomain_count', 'has_at_symbol', 'has_suspicious_ext',
            'has_port', 'path_length', 'special_char_count', 'digit_count',
            'digit_letter_ratio', 'is_shortened', 'path_depth', 
            'avg_word_length_in_path', 'domain_length', 'subdomain_to_domain_ratio',
            'contains_brand_name', 'multiple_tlds', 'has_https_in_path',
            'host_contains_digits', 'entropy', 'is_domain_ip', 'domain_only_length',
            'keyword_in_domain', 'keyword_in_path', 'keyword_in_query',
            'meaningful_words_ratio', 'word_to_length_ratio', 'is_domain_in_dictionary',
            'is_common_tld', 'domain_entropy', 'path_entropy', 'max_consecutive_consonants',
            'has_punycode', 'lexical_diversity', 'path_semantic_score',
            'url_structure_pattern', 'is_restricted_tld', 'has_official_terms', 
            'has_media_terms', 'domain_age_influence', 'readability_score', 'is_popular_domain'
        ]
        
        # Create a DataFrame with the features (using only the available columns)
        X_df = pd.DataFrame(X_features, columns=all_feature_names[:X_features.shape[1]])
        
        # Get the domain parts for additional information
        parts = self.feature_extractor._parse_url(url)
        domain_parts = self.feature_extractor._extract_domain_parts(parts["hostname"])
        
        return X_df, domain_parts, parts["hostname"]
    
    def predict(self, url):
        """Predict if a URL is phishing or benign"""
        # Extract features
        X_df, domain_parts, domain = self.extract_features(url)
        
        # Select only the features used by the model
        X_selected = X_df[self.selected_features]
        
        # Make prediction
        prediction = self.model.predict(X_selected)[0]
        
        # Get decision score
        if hasattr(self.model, "decision_function"):
            decision_score = self.model.decision_function(X_selected)[0]
            # Convert to a confidence value between 0-1 (sigmoid function)
            confidence = 1 / (1 + np.exp(-np.abs(decision_score)))
            # Calculate probability that the URL is phishing (positive class)
            phishing_probability = 1 / (1 + np.exp(-decision_score))
        else:
            decision_score = 0
            confidence = 0
            phishing_probability = 0.5
            
        # Determine result label
        result = "benign" if prediction == 0 else "phishing"
        
        return {
            "url": url,
            "domain": domain,
            "domain_parts": domain_parts,
            "features": X_df[self.selected_features].iloc[0].to_dict(),
            "prediction": result,
            "confidence": confidence,
            "phishing_probability": phishing_probability,
            "feature_selection": True,
            "selected_features": self.selected_features
        }
    
    def explain_prediction(self, url):
        """Predict and explain the factors influencing the prediction"""
        # Extract features
        X_df, domain_parts, domain = self.extract_features(url)
        
        # Select only the features used by the model
        X_selected = X_df[self.selected_features]
        
        # Make prediction
        prediction = self.model.predict(X_selected)[0]
        
        # Get decision score
        if hasattr(self.model, "decision_function"):
            decision_score = self.model.decision_function(X_selected)[0]
            # Convert to a confidence value between 0-1 (sigmoid function)
            confidence = 1 / (1 + np.exp(-np.abs(decision_score)))
            # Calculate probability that the URL is phishing (positive class)
            phishing_probability = 1 / (1 + np.exp(-decision_score))
        else:
            decision_score = 0
            confidence = 0
            phishing_probability = 0.5
            
        # Determine result label
        result = "benign" if prediction == 0 else "phishing"
        
        # Calculate feature impacts (coefficient * feature value)
        feature_impacts = []
        for i, feature_name in enumerate(self.selected_features):
            feature_value = X_selected[feature_name].values[0]
            coefficient = self.model.coef_[0][i]
            impact = feature_value * coefficient
            contribution = "benign" if impact < 0 else "phishing"
            
            feature_impacts.append({
                "name": feature_name,
                "value": feature_value,
                "coefficient": coefficient,
                "impact": abs(impact),
                "contribution": contribution
            })
        
        # Sort features by absolute impact
        feature_impacts.sort(key=lambda x: x["impact"], reverse=True)
        
        # Prepare full result
        result_data = {
            "url": url,
            "domain": domain,
            "domain_parts": domain_parts,
            "features": X_df[self.selected_features].iloc[0].to_dict(),
            "prediction": result,
            "confidence": confidence,
            "phishing_probability": phishing_probability,
            "feature_selection": True,
            "selected_features": self.selected_features,
            "feature_impacts": feature_impacts
        }
        
        return result_data


def main():
    """Main function for CLI interface"""
    parser = argparse.ArgumentParser(description="Predict if a URL is phishing or benign")
    parser.add_argument("url", help="URL to analyze")
    parser.add_argument("--explain", action="store_true", help="Show detailed explanation of prediction")
    args = parser.parse_args()
    
    try:
        # Create predictor
        predictor = URLPredictor()
        
        # Predict and explain
        if args.explain:
            result = predictor.explain_prediction(args.url)
        else:
            result = predictor.predict(args.url)
        
        # Print prediction result
        print(f"\n[+] URL: {result['url']}")
        print(f"[+] Domain: {result['domain']}")
        print(f"[+] Prediction: {result['prediction'].upper()}")
        print(f"[+] Confidence: {result['confidence']:.4f}")
        print(f"[+] Phishing Probability: {result['phishing_probability']:.4f}")
        
        # Print domain parts
        print(f"\n[+] Domain Analysis:")
        print(f"    Subdomain: {result['domain_parts']['subdomain']}")
        print(f"    Domain: {result['domain_parts']['domain']}")
        print(f"    TLD: {result['domain_parts']['tld']}")
        
        # If explanation requested, show feature impacts
        if args.explain:
            print(f"\n[+] Top Feature Impacts:")
            for i, feature in enumerate(result["feature_impacts"][:10]):  # Show top 10
                direction = "→ Indicates phishing" if feature["contribution"] == "phishing" else "→ Indicates benign"
                print(f"    {i+1}. {feature['name']} = {feature['value']:.2f} " +
                      f"(impact: {feature['impact']:.2f}, {direction})")
        
        # Always save the results to prediction_results/python_prediction.json
        output_path = Path('prediction_results/python_prediction.json')
        # Create directory if it doesn't exist
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"\n[+] Detailed results saved to {output_path}")
            
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
