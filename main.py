import numpy as np
import re
from collections import Counter
import sys


class PasswordStrengthAnalyzer:
    def __init__(self):
        self.max_length = 30

    def analyze_password(self, password):
        # Basic checks
        checks = {
            'length': len(password) >= 8,
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'lowercase': bool(re.search(r'[a-z]', password)),
            'numbers': bool(re.search(r'\d', password)),
            'special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        }

        # Calculate entropy
        char_counts = Counter(password)
        entropy = sum(-count / len(password) * np.log2(count / len(password))
                      for count in char_counts.values())

        # Calculate basic strength score based on checks and entropy
        base_score = (sum(checks.values()) / len(checks)) * 0.7
        entropy_score = min(entropy / 4, 1) * 0.3  # Normalize entropy contribution
        strength_score = base_score + entropy_score

        return {
            'checks': checks,
            'entropy': entropy,
            'strength_score': strength_score,
            'recommendations': self._generate_recommendations(checks, password)
        }

    def _generate_recommendations(self, checks, password):
        recommendations = []
        if not checks['length']:
            recommendations.append('Make the password at least 8 characters long')
        if not checks['uppercase']:
            recommendations.append('Add uppercase letters')
        if not checks['lowercase']:
            recommendations.append('Add lowercase letters')
        if not checks['numbers']:
            recommendations.append('Add numbers')
        if not checks['special']:
            recommendations.append('Add special characters')

        # Additional pattern checks
        if len(set(password)) < len(password) * 0.7:
            recommendations.append('Use more unique characters')
        if re.search(r'(.)\1{2,}', password):
            recommendations.append('Avoid repeating characters more than twice')
        if len(password) < 12:
            recommendations.append('Consider using a longer password (12+ characters recommended)')

        return recommendations


def print_color(text, color_code):
    """Print text in color in the console."""
    print(f"\033[{color_code}m{text}\033[0m")


def main():
    analyzer = PasswordStrengthAnalyzer()

    print_color("\nPassword Strength Analyzer", "1;36")  # Cyan text
    print_color("=" * 50, "1;36")

    while True:
        try:
            password = input("\nEnter a password to analyze (or 'quit' to exit): ")
            if password.lower() == 'quit':
                break

            results = analyzer.analyze_password(password)

            print("\nPassword Analysis Results:")
            print_color("-" * 50, "1;34")  # Blue line

            # Print strength score with color based on value
            score = results['strength_score']
            score_color = "1;31" if score < 0.4 else "1;33" if score < 0.7 else "1;32"
            print(f"Strength Score: ", end="")
            print_color(f"{score:.2f}/1.00", score_color)

            print(f"Entropy: {results['entropy']:.2f}")

            print("\nChecks:")
            for check, passed in results['checks'].items():
                status = "✓" if passed else "✗"
                color = "1;32" if passed else "1;31"
                print_color(f"{status} {check.title()}", color)

            if results['recommendations']:
                print("\nRecommendations:")
                for rec in results['recommendations']:
                    print_color(f"• {rec}", "1;33")  # Yellow text

        except KeyboardInterrupt:
            print("\nExiting program...")
            break
        except Exception as e:
            print_color(f"\nAn error occurred: {str(e)}", "1;31")
            continue


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print_color(f"Critical error: {str(e)}", "1;31")
        sys.exit(1)