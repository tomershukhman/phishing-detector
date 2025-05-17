#!/usr/bin/env python3
"""
Feature Selection Module for Phishing URL Detection
This module analyzes feature correlations and selects optimal features.
"""
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.feature_selection import SelectKBest, f_classif, mutual_info_classif, RFE
from sklearn.linear_model import LogisticRegression

class FeatureSelector:
    """
    Class to select optimal features based on various strategies:
    - Correlation analysis
    - Feature importance ranking
    - Statistical significance
    - Recursive feature elimination
    """
    
    def __init__(self, correlation_threshold=0.85, feature_names=None):
        """
        Initialize the feature selector
        
        Args:
            correlation_threshold: Threshold for considering features as highly correlated
            feature_names: List of feature names
        """
        self.correlation_threshold = correlation_threshold
        self.feature_names = feature_names
        self.selected_features = None
        self.correlation_matrix = None
        self.dropped_features = []
        
    def fit(self, X, y=None):
        """Fit the feature selector on the data"""
        # If X is not a DataFrame, convert it to one
        if not isinstance(X, pd.DataFrame):
            if self.feature_names is not None:
                feature_names = self.feature_names[:X.shape[1]]
                X = pd.DataFrame(X, columns=feature_names)
            else:
                X = pd.DataFrame(X)
                
        # Store the original feature names
        self.feature_names = list(X.columns)
        
        # Calculate correlation matrix
        self.correlation_matrix = X.corr().abs()
        
        # Identify highly correlated features
        self.selected_features = self._remove_correlated_features(X)
        
        return self
    
    def transform(self, X):
        """Transform the dataset to keep only selected features"""
        # If X is not a DataFrame, convert it to one
        if not isinstance(X, pd.DataFrame):
            if self.feature_names is not None:
                feature_names = self.feature_names[:X.shape[1]]
                X = pd.DataFrame(X, columns=feature_names)
            else:
                X = pd.DataFrame(X)
        
        # Keep only selected features
        if self.selected_features is not None:
            # Handle case where X might have different columns than what we fit on
            columns_to_keep = [col for col in self.selected_features if col in X.columns]
            X_selected = X[columns_to_keep]
            
            # Convert back to numpy array if input was array
            if not isinstance(X, pd.DataFrame):
                X_selected = X_selected.values
                
            return X_selected
        else:
            return X
    
    def fit_transform(self, X, y=None):
        """Fit and transform in one step"""
        self.fit(X, y)
        return self.transform(X)
    
    def _remove_correlated_features(self, X):
        """
        Remove highly correlated features
        
        Strategy: For each pair of highly correlated features, keep the one with
        higher correlation with other features (more informative)
        """
        # Create a copy of the correlation matrix to avoid modifying the original
        corr_matrix = self.correlation_matrix.copy()
        
        # Set diagonal to 0 to exclude self-correlations
        np.fill_diagonal(corr_matrix.values, 0)
        
        # Track features to drop
        dropped_features = []
        
        # Iterate until no correlations above threshold
        while True:
            # Get the maximum correlation value
            max_corr = corr_matrix.max().max()
            
            # If max correlation is below threshold, break the loop
            if max_corr < self.correlation_threshold:
                break
                
            # Find the pair with maximum correlation
            max_idx = np.where(corr_matrix.values == max_corr)
            
            # If we found no indices, break
            if len(max_idx[0]) == 0:
                break
                
            # Get feature indices
            i, j = max_idx[0][0], max_idx[1][0]
            
            # Get feature names
            feature_i = corr_matrix.index[i]
            feature_j = corr_matrix.index[j]
            
            # Decide which feature to drop
            # Strategy: drop the feature with lower mean absolute correlation with other features
            avg_corr_i = corr_matrix.loc[feature_i].mean()
            avg_corr_j = corr_matrix.loc[feature_j].mean()
            
            drop_feature = feature_i if avg_corr_i < avg_corr_j else feature_j
            keep_feature = feature_j if drop_feature == feature_i else feature_i
            
            # Drop the feature with lower mean correlation
            dropped_features.append((drop_feature, keep_feature, max_corr))
            
            # Remove the feature from the correlation matrix
            corr_matrix.drop(drop_feature, axis=0, inplace=True)
            corr_matrix.drop(drop_feature, axis=1, inplace=True)
        
        # Store dropped features for reporting
        self.dropped_features = dropped_features
        
        # Return selected features
        selected_features = [col for col in X.columns if col not in [item[0] for item in dropped_features]]
        return selected_features
        
    def get_selected_features(self):
        """Return the list of selected features"""
        return self.selected_features
    
    def get_dropped_features_info(self):
        """Return information about dropped features and their replacements"""
        return [(drop, keep, corr) for drop, keep, corr in self.dropped_features]
    
    def plot_correlation_matrix(self, output_path=None, figsize=(14, 12)):
        """Plot the correlation matrix heatmap"""
        if self.correlation_matrix is None:
            print("Error: Correlation matrix not computed. Call fit() first.")
            return
            
        plt.figure(figsize=figsize)
        mask = np.triu(np.ones_like(self.correlation_matrix, dtype=bool))
        
        # Generate heatmap with lower triangle
        sns.heatmap(self.correlation_matrix, mask=mask, annot=False, cmap='coolwarm', 
                    vmax=1, vmin=0, linewidths=0.5, cbar_kws={"shrink": .8})
        plt.title('Feature Correlation Matrix')
        plt.tight_layout()
        
        if output_path:
            plt.savefig(output_path)
            print(f"Correlation matrix saved to {output_path}")
            # Only close the plot if saving to file
            plt.close()
        
    def plot_feature_importance(self, X, y, top_n=20, output_path=None):
        """
        Plot feature importance using multiple methods
        
        Args:
            X: Features
            y: Target
            top_n: Number of top features to display
            output_path: Path to save the plot
        """
        # Convert X to DataFrame if it's not already
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X, columns=self.feature_names[:X.shape[1]])
            
        # Calculate feature importance using ANOVA F-value
        f_selector = SelectKBest(f_classif, k='all')
        f_selector.fit(X, y)
        f_scores = f_selector.scores_
        
        # Calculate mutual information
        mi_selector = SelectKBest(mutual_info_classif, k='all')
        mi_selector.fit(X, y)
        mi_scores = mi_selector.scores_
        
        # Create a DataFrame of features and their importance scores
        importance_df = pd.DataFrame({
            'Feature': X.columns,
            'F-Score': f_scores,
            'Mutual Information': mi_scores
        })
        
        # Sort by F-score
        importance_df = importance_df.sort_values('F-Score', ascending=False).head(top_n)
        
        # Plot
        plt.figure(figsize=(12, 8))
        
        plt.subplot(1, 2, 1)
        sns.barplot(y='Feature', x='F-Score', data=importance_df)
        plt.title('Feature Importance (F-Score)')
        plt.tight_layout()
        
        plt.subplot(1, 2, 2)
        sns.barplot(y='Feature', x='Mutual Information', data=importance_df)
        plt.title('Feature Importance (Mutual Information)')
        plt.tight_layout()
        
        if output_path:
            plt.savefig(output_path)
            print(f"Feature importance plot saved to {output_path}")
            # Only close the plot if saving to file
            plt.close()
        
        return importance_df
    
    def select_features_with_rfe(self, X, y, n_features=30):
        """
        Select features using Recursive Feature Elimination
        
        Args:
            X: Features
            y: Target
            n_features: Number of features to select
            
        Returns:
            List of selected feature names
        """
        # Convert X to DataFrame if it's not already
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X, columns=self.feature_names[:X.shape[1]])
            
        # Initialize the RFE model
        estimator = LogisticRegression(solver='liblinear', class_weight='balanced', max_iter=1000, random_state=42)
        selector = RFE(estimator, n_features_to_select=n_features, step=1, verbose=0)
        
        # Fit the RFE model
        selector = selector.fit(X, y)
        
        # Get the selected features
        selected_features = X.columns[selector.support_].tolist()
        
        return selected_features