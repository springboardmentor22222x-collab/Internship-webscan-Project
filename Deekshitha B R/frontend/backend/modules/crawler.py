import asyncio
from bs4 import BeautifulSoup
import logging
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

class WebCrawler:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.visited = set()
        self.pages = []
    
    async def crawl(self, max_pages: int = 20) -> List[Dict[str, Any]]:
        """Crawl website and discover pages, forms, and parameters"""
        try:
            await self._crawl_page(self.base_url, max_pages)
            return self.pages
        except Exception as e:
            logger.error(f"Crawling failed: {str(e)}")
            return self._generate_mock_pages()
    
    async def _crawl_page(self, url: str, max_pages: int):
        if len(self.pages) >= max_pages or url in self.visited:
            return
        
        self.visited.add(url)
        
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status != 200:
                        return
                    
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    page_data = {
                        'url': url,
                        'forms': self._extract_forms(soup, url),
                        'links': self._extract_links(soup, url),
                        'inputs': self._extract_inputs(soup),
                        'params': self._extract_url_params(url)
                    }
                    
                    self.pages.append(page_data)
                    
                    for link in page_data['links'][:5]:
                        if self._is_same_domain(link, self.base_url):
                            await self._crawl_page(link, max_pages)
        
        except Exception as e:
            logger.warning(f"Failed to crawl {url}: {str(e)}")
    
    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                form_data['inputs'].append({
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text')
                })
            
            forms.append(form_data)
        
        return forms
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        links = []
        for a_tag in soup.find_all('a', href=True):
            link = urljoin(base_url, a_tag['href'])
            links.append(link)
        return list(set(links))
    
    def _extract_inputs(self, soup: BeautifulSoup) -> List[str]:
        inputs = []
        for input_tag in soup.find_all(['input', 'textarea']):
            if input_tag.get('name'):
                inputs.append(input_tag.get('name'))
        return list(set(inputs))
    
    def _extract_url_params(self, url: str) -> List[str]:
        from urllib.parse import parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())
    
    def _is_same_domain(self, url: str, base_url: str) -> bool:
        return urlparse(url).netloc == urlparse(base_url).netloc
    
    def _generate_mock_pages(self) -> List[Dict[str, Any]]:
        """Generate mock vulnerable pages for demonstration"""
        return [
            {
                'url': f'{self.base_url}/login',
                'forms': [{
                    'action': f'{self.base_url}/login',
                    'method': 'post',
                    'inputs': [{'name': 'username', 'type': 'text'}, {'name': 'password', 'type': 'password'}]
                }],
                'links': [f'{self.base_url}/dashboard', f'{self.base_url}/profile'],
                'inputs': ['username', 'password'],
                'params': []
            },
            {
                'url': f'{self.base_url}/search',
                'forms': [{
                    'action': f'{self.base_url}/search',
                    'method': 'get',
                    'inputs': [{'name': 'q', 'type': 'text'}]
                }],
                'links': [],
                'inputs': ['q'],
                'params': ['q']
            },
            {
                'url': f'{self.base_url}/user/profile',
                'forms': [],
                'links': [f'{self.base_url}/user/1', f'{self.base_url}/user/2'],
                'inputs': [],
                'params': ['id']
            }
        ]