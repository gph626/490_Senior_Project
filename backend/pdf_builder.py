"""
Custom PDF Builder Module
Provides functionality to create custom PDFs with text, charts, and images.
"""

import io
import base64
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.platypus import Paragraph, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib import colors
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


class CustomPDFBuilder:
    """Builder class for creating custom PDFs with various elements."""
    
    def __init__(self, title="Custom Report"):
        """Initialize PDF builder with a title."""
        self.title = title
        self.elements = []
        self.page_width, self.page_height = letter
        self.margin = 72  # 1 inch margins
        self.current_y = self.page_height - self.margin
        
    def add_title(self, text, font_size=24, alignment="center"):
        """Add a title to the PDF."""
        self.elements.append({
            'type': 'title',
            'text': text,
            'font_size': font_size,
            'alignment': alignment
        })
        
    def add_heading(self, text, font_size=16, alignment="left"):
        """Add a heading to the PDF."""
        self.elements.append({
            'type': 'heading',
            'text': text,
            'font_size': font_size,
            'alignment': alignment
        })
        
    def add_paragraph(self, text, font_size=11, alignment="left"):
        """Add a paragraph to the PDF."""
        self.elements.append({
            'type': 'paragraph',
            'text': text,
            'font_size': font_size,
            'alignment': alignment
        })
        
    def add_chart(self, chart_data, chart_type="bar", title="", width=5, height=3):
        """
        Add a chart to the PDF.
        
        Args:
            chart_data: Dict with 'labels' and 'values' keys
            chart_type: Type of chart ('bar', 'line', 'pie')
            title: Chart title
            width: Chart width in inches
            height: Chart height in inches
        """
        self.elements.append({
            'type': 'chart',
            'chart_type': chart_type,
            'data': chart_data,
            'title': title,
            'width': width,
            'height': height
        })
        
    def add_image(self, image_data, width=4, height=3, caption=""):
        """Add an image to the PDF from base64 data."""
        self.elements.append({
            'type': 'image',
            'data': image_data,
            'width': width,
            'height': height,
            'caption': caption
        })
        
    def add_spacer(self, height=0.5):
        """Add vertical space."""
        self.elements.append({
            'type': 'spacer',
            'height': height
        })
        
    def add_page_break(self):
        """Add a page break."""
        self.elements.append({
            'type': 'page_break'
        })
        
    def _draw_text_element(self, pdf, element, y):
        """Draw text elements (title, heading, paragraph)."""
        text = element['text']
        font_size = element['font_size']
        alignment = element['alignment']
        
        # Set font based on type
        if element['type'] == 'title':
            pdf.setFont("Helvetica-Bold", font_size)
        elif element['type'] == 'heading':
            pdf.setFont("Helvetica-Bold", font_size)
        else:
            pdf.setFont("Helvetica", font_size)
        
        # Calculate x position based on alignment
        text_width = pdf.stringWidth(text, pdf._fontname, font_size)
        
        if alignment == "center":
            x = (self.page_width - text_width) / 2
        elif alignment == "right":
            x = self.page_width - self.margin - text_width
        else:  # left
            x = self.margin
            
        # Handle multi-line text
        max_width = self.page_width - (2 * self.margin)
        lines = []
        words = text.split()
        current_line = []
        
        for word in words:
            test_line = ' '.join(current_line + [word])
            if pdf.stringWidth(test_line, pdf._fontname, font_size) <= max_width:
                current_line.append(word)
            else:
                if current_line:
                    lines.append(' '.join(current_line))
                current_line = [word]
        if current_line:
            lines.append(' '.join(current_line))
        
        # Draw each line
        for line in lines:
            if y < self.margin + font_size:
                pdf.showPage()
                y = self.page_height - self.margin
                
            if alignment == "center":
                line_width = pdf.stringWidth(line, pdf._fontname, font_size)
                x = (self.page_width - line_width) / 2
            elif alignment == "right":
                line_width = pdf.stringWidth(line, pdf._fontname, font_size)
                x = self.page_width - self.margin - line_width
            else:
                x = self.margin
                
            pdf.drawString(x, y, line)
            y -= font_size + 4
            
        return y - 10  # Add extra space after element
        
    def _draw_chart(self, pdf, element, y):
        """Draw a chart element."""
        chart_data = element['data']
        chart_type = element['chart_type']
        title = element.get('title', '')
        width = element['width'] * inch
        height = element['height'] * inch
        
        # Check if enough space on page
        if y - height < self.margin:
            pdf.showPage()
            y = self.page_height - self.margin
        
        # Create matplotlib figure
        fig, ax = plt.subplots(figsize=(element['width'], element['height']))
        
        # Handle different data formats
        if isinstance(chart_data, list):
            # For time series data like [{"date": "...", "critical": 5, ...}, ...]
            labels = []
            values = []
            if chart_data:
                # Extract dates as labels
                labels = [item.get('date', '') for item in chart_data]
                # For stacked data, we'll just sum all numeric values for now
                # A more sophisticated approach would handle stacked charts properly
                value_keys = [k for k in chart_data[0].keys() if k != 'date']
                if value_keys:
                    # Just take the first numeric key for simple charts
                    values = [sum(item.get(k, 0) for k in value_keys if isinstance(item.get(k), (int, float))) 
                             for item in chart_data]
        else:
            # For dict format like {"labels": [...], "values": [...]}
            labels = chart_data.get('labels', [])
            values = chart_data.get('values', [])
        
        if chart_type == 'bar':
            ax.bar(labels, values, color='#4A90E2')
            ax.set_ylabel('Count')
        elif chart_type == 'line':
            ax.plot(labels, values, marker='o', linewidth=2, color='#4A90E2')
            ax.set_ylabel('Value')
        elif chart_type == 'pie':
            ax.pie(values, labels=labels, autopct='%1.1f%%', startangle=90)
            ax.axis('equal')
        
        if title and chart_type != 'pie':
            ax.set_title(title)
            
        plt.tight_layout()
        
        # Save to buffer
        img_buffer = io.BytesIO()
        plt.savefig(img_buffer, format='png', dpi=150, bbox_inches='tight')
        plt.close(fig)
        img_buffer.seek(0)
        
        # Draw image on PDF
        img = ImageReader(img_buffer)
        pdf.drawImage(img, self.margin, y - height, width=width, height=height)
        
        return y - height - 20
        
    def _draw_image(self, pdf, element, y):
        """Draw an image element."""
        width = element['width'] * inch
        height = element['height'] * inch
        caption = element.get('caption', '')
        
        # Check if enough space on page
        if y - height < self.margin:
            pdf.showPage()
            y = self.page_height - self.margin
        
        # Decode base64 image
        try:
            image_data = element['data']
            if ',' in image_data:
                image_data = image_data.split(',')[1]
            img_bytes = base64.b64decode(image_data)
            img_buffer = io.BytesIO(img_bytes)
            img = ImageReader(img_buffer)
            
            # Center the image
            x = (self.page_width - width) / 2
            pdf.drawImage(img, x, y - height, width=width, height=height)
            
            y -= height + 10
            
            # Add caption if provided
            if caption:
                pdf.setFont("Helvetica-Oblique", 10)
                caption_width = pdf.stringWidth(caption, "Helvetica-Oblique", 10)
                caption_x = (self.page_width - caption_width) / 2
                pdf.drawString(caption_x, y, caption)
                y -= 20
                
        except Exception as e:
            # Draw error message if image fails
            pdf.setFont("Helvetica", 10)
            pdf.drawString(self.margin, y, f"[Image could not be loaded: {str(e)}]")
            y -= 20
            
        return y
        
    def generate_pdf(self):
        """Generate the PDF and return as bytes."""
        buffer = io.BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=letter)
        pdf.setTitle(self.title)
        
        y = self.page_height - self.margin
        
        for element in self.elements:
            elem_type = element['type']
            
            if elem_type in ['title', 'heading', 'paragraph']:
                y = self._draw_text_element(pdf, element, y)
            elif elem_type == 'chart':
                y = self._draw_chart(pdf, element, y)
            elif elem_type == 'image':
                y = self._draw_image(pdf, element, y)
            elif elem_type == 'spacer':
                y -= element['height'] * inch
            elif elem_type == 'page_break':
                pdf.showPage()
                y = self.page_height - self.margin
                
            # Check if we need a new page
            if y < self.margin:
                pdf.showPage()
                y = self.page_height - self.margin
        
        # Add footer with date and page numbers
        page_num = 1
        total_pages = pdf.getPageNumber()
        
        pdf.save()
        buffer.seek(0)
        return buffer.getvalue()


def create_pdf_from_config(config):
    """
    Create a PDF from a configuration dictionary.
    
    Args:
        config: Dict containing title and elements list
        
    Returns:
        PDF bytes
    """
    builder = CustomPDFBuilder(title=config.get('title', 'Custom Report'))
    
    for element in config.get('elements', []):
        elem_type = element.get('type')
        
        if elem_type == 'title':
            builder.add_title(
                element.get('text', ''),
                font_size=element.get('fontSize', 24),
                alignment=element.get('alignment', 'center')
            )
        elif elem_type == 'heading':
            builder.add_heading(
                element.get('text', ''),
                font_size=element.get('fontSize', 16),
                alignment=element.get('alignment', 'left')
            )
        elif elem_type == 'paragraph':
            builder.add_paragraph(
                element.get('text', ''),
                font_size=element.get('fontSize', 11),
                alignment=element.get('alignment', 'left')
            )
        elif elem_type == 'chart':
            builder.add_chart(
                chart_data=element.get('data', {}),
                chart_type=element.get('chartType', 'bar'),
                title=element.get('title', ''),
                width=element.get('width', 5),
                height=element.get('height', 3)
            )
        elif elem_type == 'image':
            builder.add_image(
                image_data=element.get('data', ''),
                width=element.get('width', 4),
                height=element.get('height', 3),
                caption=element.get('caption', '')
            )
        elif elem_type == 'spacer':
            builder.add_spacer(height=element.get('height', 0.5))
        elif elem_type == 'pageBreak':
            builder.add_page_break()
    
    return builder.generate_pdf()
