import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import json
import os
from scipy.sparse import hstack
from joblib import dump
import warnings

from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.svm import LinearSVC
from sklearn.metrics import (
    classification_report, accuracy_score, confusion_matrix,
    precision_score, recall_score, f1_score, roc_curve, roc_auc_score,
    precision_recall_curve, average_precision_score
)

from feature_extractor import URLFeatureExtractor
from feature_selection import FeatureSelector

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')

# --- Create directories ---
training_report_dir = 'training_report'
models_dir = 'models'

for directory in [training_report_dir, models_dir]:
    if not os.path.exists(directory):
        os.makedirs(directory)

# --- Load Dataset ---
print("[+] Loading dataset...")
df = pd.read_csv('data/balanced_urls.csv')  # Must contain 'url' and 'result'
df.dropna(subset=['url', 'result'], inplace=True)

X_raw = df['url'].astype(str)
y = df['result'].astype(int)

# --- Feature Extraction ---
print("[+] Extracting features (this may take a while for large datasets)...")
custom_extractor = URLFeatureExtractor()

# Define all feature names for reference
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
    # NLP-based features
    'meaningful_words_ratio', 'word_to_length_ratio', 'is_domain_in_dictionary',
    'is_common_tld', 'domain_entropy', 'path_entropy', 'max_consecutive_consonants',
    'has_punycode', 'lexical_diversity',
    # Advanced features
    'path_semantic_score', 'url_structure_pattern', 'is_restricted_tld',
    'has_official_terms', 'has_media_terms', 'domain_age_influence', 
    'readability_score', 'is_popular_domain'
]

# Extract features
X_custom = custom_extractor.fit_transform(X_raw)

# Convert to DataFrame for better feature handling
X_df = pd.DataFrame(X_custom, columns=all_feature_names[:X_custom.shape[1]])
print(f"[+] Extracted {X_df.shape[1]} features from {X_df.shape[0]} URLs")

# --- Feature Selection ---
print("[+] Performing feature selection...")
# Initialize feature selector with correlation threshold of 0.8
feature_selector = FeatureSelector(correlation_threshold=0.8, feature_names=all_feature_names)

# Fit feature selector to data
feature_selector.fit(X_df)

# Generate correlation matrix plot
feature_selector.plot_correlation_matrix(output_path=f'{training_report_dir}/feature_correlation_matrix.png')

# Generate feature importance plots
importance_df = feature_selector.plot_feature_importance(X_df, y, output_path=f'{training_report_dir}/feature_importance_analysis.png')

# Get selected features
selected_features = feature_selector.get_selected_features()
print(f"[+] Selected {len(selected_features)} features out of {X_df.shape[1]} after correlation analysis")

# Additional feature selection using RFE (more aggressive selection)
rfe_features = feature_selector.select_features_with_rfe(X_df, y, n_features=min(30, len(selected_features)))
print(f"[+] Selected {len(rfe_features)} features using Recursive Feature Elimination")

# Print feature selection information
dropped_info = feature_selector.get_dropped_features_info()
if dropped_info:
    print("\n[+] Dropped features due to high correlation:")
    for drop, keep, corr in dropped_info:
        print(f"  - Dropped '{drop}' (kept '{keep}', correlation: {corr:.4f})")

# Extract the selected features only
X_selected = X_df[rfe_features]

# --- Train/Test Split ---
print("[+] Splitting data into training and test sets...")
X_train, X_test, y_train, y_test = train_test_split(
    X_selected, y, test_size=0.2, stratify=y, random_state=42
)

# --- Define Models with Hyperparameter Tuning ---
print("[+] Setting up LinearSVC model for hyperparameter tuning...")
# Only keep LinearSVC model
models = {
    'LinearSVC': LinearSVC(class_weight='balanced', max_iter=10000, random_state=42)
}

# Define hyperparameter grids for LinearSVC only
param_grids = {
    'LinearSVC': {'C': [0.1, 1.0, 10.0]}
}

# --- Train and Evaluate Models ---
results = {}
cm_figs = []
best_models = {}

print("\n[+] Training and tuning LinearSVC...")
model = models['LinearSVC']

# Hyperparameter tuning with cross-validation
grid_search = GridSearchCV(
    model, param_grids['LinearSVC'], cv=3, scoring='f1', n_jobs=1
)
grid_search.fit(X_train, y_train)

# Get the best model
best_model = grid_search.best_estimator_
best_models['LinearSVC'] = best_model

print(f"    Best parameters: {grid_search.best_params_}")
print(f"    Best cross-validation score: {grid_search.best_score_:.4f}")

# Evaluate on test set
print(f"[+] Evaluating LinearSVC on test set...")
y_pred = best_model.predict(X_test)

# For probabilistic predictions (if applicable)
if hasattr(best_model, "decision_function"):
    y_score = best_model.decision_function(X_test)
else:
    y_score = y_pred

# Calculate metrics
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

report = classification_report(y_test, y_pred, digits=4)
cm = confusion_matrix(y_test, y_pred)

# Try to calculate ROC AUC
try:
    roc_auc = roc_auc_score(y_test, y_score)
except:
    roc_auc = None

# Store results
results['LinearSVC'] = {
    'accuracy': accuracy,
    'precision': precision,
    'recall': recall,
    'f1': f1,
    'roc_auc': roc_auc,
    'report': report,
    'confusion_matrix': cm,
    'y_score': y_score
}

# Create and save confusion matrix plot
plt.figure(figsize=(6, 4))
labels = ['Benign (0)', 'Malicious (1)']
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=labels, yticklabels=labels)
plt.title('Confusion Matrix - LinearSVC')
plt.xlabel('Predicted Label')
plt.ylabel('True Label')
plt.tight_layout()

# Save individual plot
plt.savefig(f'{training_report_dir}/LinearSVC_confusion_matrix.png')
cm_figs.append(plt)

# --- Generate ROC curves ---
print("\n[+] Generating ROC curve for LinearSVC...")
plt.figure(figsize=(10, 8))

if results['LinearSVC']['roc_auc'] is not None:
    fpr, tpr, _ = roc_curve(y_test, results['LinearSVC']['y_score'])
    plt.plot(fpr, tpr, label=f'LinearSVC (AUC = {results["LinearSVC"]["roc_auc"]:.4f})')

plt.plot([0, 1], [0, 1], 'k--', label='Random')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('ROC Curve')
plt.legend()
plt.grid(alpha=0.3)
plt.savefig(f'{training_report_dir}/roc_curve.png')

# --- Save Models ---
print("\n[+] Saving LinearSVC model...")
print(f"    Saving LinearSVC as the primary model...")
dump(best_models['LinearSVC'], f'{models_dir}/svm_model.joblib')
dump(custom_extractor, f'{models_dir}/custom_extractor.joblib')
dump(feature_selector, f'{models_dir}/feature_selector.joblib')

# Save selected features for future reference
with open(f'{models_dir}/selected_features.json', 'w') as f:
    json.dump({
        'correlation_selected': selected_features,
        'rfe_selected': rfe_features
    }, f, indent=2)

# Export model metadata for TypeScript
print("    Exporting model metadata for the browser extension...")
model_metadata = {
    "intercept": float(best_models['LinearSVC'].intercept_[0]),
    "coefficients": best_models['LinearSVC'].coef_[0].tolist(),
    "feature_names": rfe_features,
    "suspicious_keywords": ["login", "signin", "bank", "account", "update", "verify", "secure", "password"]
}

with open('../phishing-detector-extension/model_metadata.json', 'w') as f:
    json.dump(model_metadata, f)

# Force SVM to be the main model by printing it prominently
print("\n[***] LinearSVC is the primary model for predictions [***]")

# Comment out side-by-side comparison since we only have one model now
# --- Create simplified metrics report ---
print("[+] Generating metrics report...")
with open(f'{training_report_dir}/model_comparison_report.txt', 'w') as f:
    f.write("=== PHISHING DETECTION MODEL REPORT ===\n\n")
    
    # Feature selection summary
    f.write("FEATURE SELECTION SUMMARY:\n")
    f.write(f"Total features extracted: {X_df.shape[1]}\n")
    f.write(f"Features after correlation analysis: {len(selected_features)}\n")
    f.write(f"Features after RFE: {len(rfe_features)}\n\n")
    f.write(f"Final features used: {', '.join(rfe_features)}\n\n")
    
    # Dropped features info
    if dropped_info:
        f.write("Dropped features due to high correlation:\n")
        for drop, keep, corr in dropped_info:
            f.write(f"- Dropped '{drop}' (kept '{keep}', correlation: {corr:.4f})\n")
        f.write("\n")
    
    # LinearSVC metrics table
    f.write("SUMMARY METRICS:\n")
    f.write(
        f"{'Model':<20} {'Accuracy':<10} {'Precision':<10} {'Recall':<10} {'F1-Score':<10} {'ROC-AUC':<10}\n")
    f.write("-" * 70 + "\n")
    
    result = results['LinearSVC']
    roc_str = f"{result['roc_auc']:.4f}" if result['roc_auc'] is not None else "N/A"
    f.write(
        f"{'LinearSVC':<20} {result['accuracy']:<10.4f} {result['precision']:<10.4f} {result['recall']:<10.4f} {result['f1']:<10.4f} {roc_str:<10}\n")
    
    f.write("\n\n")
    
    # Detailed report for LinearSVC
    f.write("DETAILED CLASSIFICATION REPORT:\n\n")
    f.write(f"=== LinearSVC ===\n")
    f.write(result['report'])
    f.write("\n\n")

print(f"[+] Results saved to {training_report_dir}/")

# --- Feature Importance Analysis ---
print("\n[+] Analyzing feature importance for selected features...")

# Get feature importance for LinearSVC
# Get feature importances from SVM coefficients
feature_importances = np.abs(best_models['LinearSVC'].coef_[0])

# Create a dataframe for display
importance_df = pd.DataFrame({
    'Feature': rfe_features[:len(feature_importances)],
    'Importance': feature_importances,
    'Sign': ['Positive (Phishing)' if best_models['LinearSVC'].coef_[0][i] > 0 else 'Negative (Benign)' for i in range(len(feature_importances))],
    'Raw_Coefficient': best_models['LinearSVC'].coef_[0]
})

# Sort by importance
importance_df = importance_df.sort_values('Importance', ascending=False)

# Save feature importance to a dedicated JSON file for easy reference
importance_json = importance_df.to_dict(orient='records')
with open(f'{models_dir}/svc_feature_importance.json', 'w') as f:
    json.dump(importance_json, f, indent=2)
print(f"[+] SVC feature importance saved to {models_dir}/svc_feature_importance.json")

# Also save as CSV for easier viewing in spreadsheet software
importance_df.to_csv(f'{models_dir}/svc_feature_importance.csv', index=False)
print(f"[+] SVC feature importance saved to {models_dir}/svc_feature_importance.csv")

# Display the table
print("\nSelected Feature Importance (LinearSVC):")
print(importance_df.to_string(index=False))

# Plot feature importance
plt.figure(figsize=(12, 8))
bars = sns.barplot(x='Importance', y='Feature',
                data=importance_df, hue='Sign', dodge=False)
plt.title('Selected Feature Importance (LinearSVC)')
plt.tight_layout()
plt.savefig(f'{training_report_dir}/selected_feature_importance.png')

# Plot actual coefficients (not just absolute values)
print("[+] Creating LinearSVC coefficient plot...")
plt.figure(figsize=(14, 10))

# Create color palette based on the sign
colors = ['#ff5555' if sign == 'Positive (Phishing)' else '#5555ff' for sign in importance_df['Sign']]

# Plot coefficients with colors indicating direction
plt.barh(importance_df['Feature'], importance_df['Raw_Coefficient'], color=colors)

# Add gridlines
plt.grid(axis='x', linestyle='--', alpha=0.7)

# Add title and labels
plt.title('LinearSVC Coefficients (Features)', fontsize=16)
plt.xlabel('Coefficient Value (+ for Phishing, - for Benign)', fontsize=12)
plt.ylabel('Features', fontsize=12)

# Add a vertical line at x=0
plt.axvline(x=0, color='black', linestyle='-', alpha=0.5)

# Add a legend
phishing_patch = plt.Rectangle((0, 0), 1, 1, fc='#ff5555')
benign_patch = plt.Rectangle((0, 0), 1, 1, fc='#5555ff')
plt.legend([phishing_patch, benign_patch], ['Indicates Phishing', 'Indicates Benign'], loc='lower right')

# Adjust layout
plt.tight_layout()

# Save the plot
plt.savefig(f'{training_report_dir}/svc_coefficient_plot.png')
print(f"[+] Saved LinearSVC coefficient plot to {training_report_dir}/svc_coefficient_plot.png")

print("\n[+] Training completed successfully!")
print("[+] LinearSVC model with selected features is ready for deployment.")
