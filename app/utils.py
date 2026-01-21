"""Utility functions for fetching app data."""

import requests
import re
import os
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from config import Config

# Directory to store downloaded icons
ICONS_DIR = Config.ICONS_DIR


def ensure_icons_dir():
    """Ensure the icons directory exists."""
    if not os.path.exists(ICONS_DIR):
        os.makedirs(ICONS_DIR)


def fetch_play_store_icon(package_name):
    """
    Fetch the app icon URL from Google Play Store.

    Args:
        package_name: The Android package name (e.g., 'com.whatsapp')

    Returns:
        Icon URL string or None if not found
    """
    if not package_name:
        return None

    url = f'https://play.google.com/store/apps/details?id={package_name}&hl=en'

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')

        # Method 1: Look for og:image meta tag (usually the app icon)
        og_image = soup.find('meta', property='og:image')
        if og_image and og_image.get('content'):
            icon_url = og_image['content']
            # Play Store og:image is usually the icon
            if 'googleusercontent.com' in icon_url:
                return icon_url

        # Method 2: Look for the app icon in the page structure
        # The icon is often in an img tag with specific attributes
        icon_img = soup.find('img', {'itemprop': 'image'})
        if icon_img and icon_img.get('src'):
            return icon_img['src']

        # Method 3: Search for image URLs in the page that look like app icons
        # Play Store icons are hosted on play-lh.googleusercontent.com
        for img in soup.find_all('img'):
            src = img.get('src', '') or img.get('data-src', '')
            if 'play-lh.googleusercontent.com' in src and '=w' in src:
                # Get a reasonably sized icon (256px)
                # Modify the size parameter
                icon_url = re.sub(r'=w\d+', '=w256', src)
                icon_url = re.sub(r'-h\d+', '-h256', icon_url)
                return icon_url

        return None

    except requests.RequestException as e:
        print(f"Error fetching Play Store page for {package_name}: {e}")
        return None
    except Exception as e:
        print(f"Error parsing Play Store page for {package_name}: {e}")
        return None


def download_icon(icon_url, package_name):
    """
    Download an icon and save it locally.

    Args:
        icon_url: URL of the icon to download
        package_name: Package name to use for the filename

    Returns:
        Local path to the icon or None if failed
    """
    if not icon_url or not package_name:
        return None

    ensure_icons_dir()

    # Determine file extension
    ext = '.png'  # Default to PNG
    if '.webp' in icon_url:
        ext = '.webp'
    elif '.jpg' in icon_url or '.jpeg' in icon_url:
        ext = '.jpg'

    filename = f"{package_name.replace('.', '_')}{ext}"
    filepath = os.path.join(ICONS_DIR, filename)

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    }

    try:
        response = requests.get(icon_url, headers=headers, timeout=10)
        response.raise_for_status()

        with open(filepath, 'wb') as f:
            f.write(response.content)

        # Return the URL path for use in templates
        return f"/icons/{filename}"

    except Exception as e:
        print(f"Error downloading icon for {package_name}: {e}")
        return None


def fetch_and_save_icon(package_name):
    """
    Fetch icon from Play Store and save it locally.

    Args:
        package_name: The Android package name

    Returns:
        Tuple of (local_path, remote_url) or (None, None) if failed
    """
    icon_url = fetch_play_store_icon(package_name)
    if not icon_url:
        return None, None

    local_path = download_icon(icon_url, package_name)
    return local_path, icon_url


def is_changelog_text(text):
    """
    Check if text looks like a changelog/update notes rather than app description.

    Args:
        text: The text to check

    Returns:
        True if it looks like changelog, False otherwise
    """
    if not text:
        return False

    text_lower = text.lower()

    # Common changelog indicators
    changelog_patterns = [
        r'^v?\d+\.\d+',  # Starts with version number like "1.0" or "v1.0"
        r'^\*\s',  # Starts with bullet point
        r'^-\s',  # Starts with dash list
        r'^what\'s new',
        r'^new in this',
        r'^changelog',
        r'^release notes',
        r'^update:',
        r'^version \d',
    ]

    for pattern in changelog_patterns:
        if re.match(pattern, text_lower):
            return True

    # Check for changelog keywords that are typically not in descriptions
    changelog_keywords = [
        'bug fix', 'bugfix', 'fixed a bug', 'fixes bug',
        'minor improvements', 'performance improvements',
        'stability improvements', 'crash fix',
        'this update', 'this version', 'in this release',
        'we\'ve fixed', 'we\'ve updated', 'we\'ve improved',
        'thanks for using', 'thanks for your feedback',
        'keep your app updated', 'update regularly',
    ]

    # If text is short and contains changelog keywords, it's likely changelog
    if len(text) < 500:
        for keyword in changelog_keywords:
            if keyword in text_lower:
                return True

    return False


def fetch_play_store_info(package_name):
    """
    Fetch app info (description, icon, name) from Google Play Store.

    Args:
        package_name: The Android package name (e.g., 'com.whatsapp')

    Returns:
        Dictionary with 'name', 'description', 'icon_url' or None if not found
    """
    if not package_name:
        return None

    url = f'https://play.google.com/store/apps/details?id={package_name}&hl=en'

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        result = {}
        candidate_descriptions = []

        # Get app name from og:title or title tag
        og_title = soup.find('meta', property='og:title')
        if og_title and og_title.get('content'):
            # Remove " - Apps on Google Play" suffix
            name = og_title['content']
            if ' - Apps on Google Play' in name:
                name = name.replace(' - Apps on Google Play', '')
            elif ' - Google Play' in name:
                name = name.replace(' - Google Play', '')
            result['name'] = name.strip()

        # Collect all potential descriptions
        # 1. og:description meta tag
        og_desc = soup.find('meta', property='og:description')
        if og_desc and og_desc.get('content'):
            candidate_descriptions.append(og_desc['content'].strip())

        # 2. meta name="description"
        meta_desc = soup.find('meta', {'name': 'description'})
        if meta_desc and meta_desc.get('content'):
            candidate_descriptions.append(meta_desc['content'].strip())

        # 3. div with itemprop="description"
        desc_div = soup.find('div', {'itemprop': 'description'})
        if desc_div:
            full_desc = desc_div.get_text(separator=' ', strip=True)
            if full_desc:
                candidate_descriptions.append(full_desc)

        # 4. Look for data-g-id="description" attribute (modern Play Store)
        desc_section = soup.find(attrs={'data-g-id': 'description'})
        if desc_section:
            full_desc = desc_section.get_text(separator=' ', strip=True)
            if full_desc:
                candidate_descriptions.append(full_desc)

        # Filter out changelog texts and pick the best description
        valid_descriptions = [d for d in candidate_descriptions if not is_changelog_text(d)]

        # If all descriptions look like changelogs, use the longest one anyway
        if not valid_descriptions and candidate_descriptions:
            valid_descriptions = candidate_descriptions

        # Pick the longest valid description (usually more complete)
        if valid_descriptions:
            result['description'] = max(valid_descriptions, key=len)

        # Get icon URL
        og_image = soup.find('meta', property='og:image')
        if og_image and og_image.get('content'):
            icon_url = og_image['content']
            if 'googleusercontent.com' in icon_url:
                result['icon_url'] = icon_url

        # If no icon from og:image, search for it
        if 'icon_url' not in result:
            for img in soup.find_all('img'):
                src = img.get('src', '') or img.get('data-src', '')
                if 'play-lh.googleusercontent.com' in src and '=w' in src:
                    icon_url = re.sub(r'=w\d+', '=w256', src)
                    icon_url = re.sub(r'-h\d+', '-h256', icon_url)
                    result['icon_url'] = icon_url
                    break

        return result if result else None

    except requests.RequestException as e:
        print(f"Error fetching Play Store page for {package_name}: {e}")
        return None
    except Exception as e:
        print(f"Error parsing Play Store page for {package_name}: {e}")
        return None


def fetch_and_update_app_info(package_name):
    """
    Fetch all available info from Play Store.

    Args:
        package_name: The Android package name

    Returns:
        Dictionary with available info or None if failed
    """
    info = fetch_play_store_info(package_name)
    if not info:
        return None

    # If we got an icon URL, try to download it
    if info.get('icon_url'):
        local_path = download_icon(info['icon_url'], package_name)
        if local_path:
            info['local_icon_path'] = local_path

    return info
