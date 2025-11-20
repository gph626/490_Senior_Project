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
        
        # Create matplotlib figure with dark background matching dashboard
        fig, ax = plt.subplots(figsize=(element['width'], element['height']))
        fig.patch.set_facecolor('#23272F')
        ax.set_facecolor('#23272F')
        
        # Configure font to match dashboard (Montserrat-like)
        plt.rcParams['font.family'] = 'sans-serif'
        plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial', 'Helvetica']
        
        # Handle different data formats
        is_stacked_severity = False
        if isinstance(chart_data, list):
            # For time series data like [{"date": "...", "critical": 5, ...}, ...]
            if not chart_data:
                labels = []
                values = []
            elif 'critical' in chart_data[0] or 'high' in chart_data[0]:
                # Stacked severity trend chart - matches dashboard severityTrendChart
                is_stacked_severity = True
                labels = [item.get('date', '') for item in chart_data]
                severity_keys = ['critical', 'high', 'medium', 'low', 'unknown']
                # Colors matching dashboard Chart.js colors exactly
                severity_colors = {
                    'critical': 'rgba(255,99,132,0.85)',
                    'high': 'rgba(255,140,0,0.85)',
                    'medium': 'rgba(255,206,86,0.85)',
                    'low': 'rgba(75,192,192,0.85)',
                    'unknown': 'rgba(153,102,255,0.85)'
                }
                
                # Convert rgba to matplotlib format
                def rgba_to_mpl(rgba_str):
                    import re
                    match = re.search(r'rgba?\((\d+),(\d+),(\d+),?([0-9.]+)?\)', rgba_str)
                    if match:
                        r, g, b = int(match.group(1))/255, int(match.group(2))/255, int(match.group(3))/255
                        a = float(match.group(4)) if match.group(4) else 1.0
                        return (r, g, b, a)
                    return (0.5, 0.5, 0.5, 1.0)
                
                # Draw stacked area chart with fill
                bottom = [0] * len(labels)
                for key in severity_keys:
                    values_data = [item.get(key, 0) for item in chart_data]
                    color_rgba = rgba_to_mpl(severity_colors[key])
                    # Fill area with transparency
                    fill_color = (color_rgba[0], color_rgba[1], color_rgba[2], 0.25)
                    ax.fill_between(range(len(labels)), bottom, [b + v for b, v in zip(bottom, values_data)], 
                                   label=key.capitalize(), color=fill_color, edgecolor=color_rgba, linewidth=1.5)
                    bottom = [b + v for b, v in zip(bottom, values_data)]
                
                # Set x-axis with rotation and reduced font size to prevent overlap
                ax.set_xticks(range(len(labels)))
                # Use rotation and smaller font size for better readability
                rotation_angle = 0 if len(labels) <= 7 else 45
                ax.set_xticklabels(labels, rotation=rotation_angle, ha='center' if len(labels) <= 7 else 'right', 
                                  color='#ffffff', fontsize=8)
                ax.legend(loc='upper left', facecolor='#23272F', edgecolor='#555', labelcolor='#ffffff', 
                         fontsize=8, framealpha=0.9)
                ax.set_ylabel('Count', color='#ffffff', fontsize=10)
                ax.tick_params(colors='#ffffff', labelsize=8)
                ax.grid(True, alpha=0.15, color='#ffffff', linestyle='-', linewidth=0.5)
                values = []  # Set empty for stacked charts
            else:
                # Simple time series
                labels = [item.get('date', '') for item in chart_data]
                value_keys = [k for k in chart_data[0].keys() if k != 'date']
                if value_keys:
                    values = [sum(item.get(k, 0) for k in value_keys if isinstance(item.get(k), (int, float))) 
                             for item in chart_data]
                else:
                    values = []
        else:
            # For dict format like {"labels": [...], "values": [...]}
            labels = chart_data.get('labels', [])
            values = chart_data.get('values', [])
        
        # Handle empty data
        if is_stacked_severity:
            # Stacked severity chart already drawn above
            pass
        elif not labels or not values:
            # Draw "No data available" message
            ax.text(0.5, 0.5, 'No data available', 
                   horizontalalignment='center', verticalalignment='center',
                   transform=ax.transAxes, color='#ffffff', fontsize=14)
            ax.set_xlim(0, 1)
            ax.set_ylim(0, 1)
            ax.axis('off')
        # Draw based on chart type
        elif chart_type == 'bar':
            # Check if this is a horizontal bar chart (top assets, etc.)
            is_horizontal = False
            if title:
                # Check for keywords that indicate horizontal layout
                title_lower = title.lower()
                horizontal_keywords = ['top', 'asset', 'risky', 'risk']
                if any(keyword in title_lower for keyword in horizontal_keywords):
                    is_horizontal = True
            
            if not is_horizontal and labels and len(labels) > 0:
                # If labels contain colons (asset:value format) or are long, use horizontal
                has_colons = any(':' in str(l) for l in labels)
                avg_label_len = sum(len(str(l)) for l in labels) / len(labels) if labels else 0
                if has_colons or avg_label_len > 12:
                    is_horizontal = True
            
            if is_horizontal:
                # Horizontal bar chart for top assets - matches dashboard
                y_pos = list(range(len(labels)))
                bars = ax.barh(y_pos, values, color=(167/255, 0/255, 29/255, 0.85), height=0.7)
                ax.set_yticks(y_pos)
                # Truncate long labels for better display
                display_labels = [str(l)[:40] + '...' if len(str(l)) > 40 else str(l) for l in labels]
                ax.set_yticklabels(display_labels, color='#ffffff', fontsize=8)
                ax.set_xlabel('Leak Count', color='#ffffff', fontsize=10)
                ax.set_ylabel('', color='#ffffff')
                ax.tick_params(axis='x', colors='#ffffff', labelsize=9)
                ax.tick_params(axis='y', colors='#ffffff', labelsize=8)
                # Invert y-axis so highest value is on top
                ax.invert_yaxis()
                # Add subtle grid
                ax.grid(True, axis='x', alpha=0.15, color='#ffffff', linestyle='-', linewidth=0.5)
                # Add value labels on bars
                for i, value in enumerate(values):
                    if value > 0:
                        ax.text(value * 0.98, i, f'{int(value)}', va='center', ha='right', 
                               color='#ffffff', fontsize=8, fontweight='bold')
            else:
                # Vertical bar chart - matches dashboard leaksChart
                x_pos = range(len(labels))
                bars = ax.bar(x_pos, values, color='#a7001d', width=0.7, edgecolor='none')
                ax.set_xticks(x_pos)
                ax.set_xticklabels(labels, rotation=0 if len(labels) <= 5 else 45, 
                                  ha='center' if len(labels) <= 5 else 'right', 
                                  color='#ffffff', fontsize=9)
                ax.set_ylabel('Count', color='#ffffff', fontsize=10)
                ax.set_xlabel('', color='#ffffff')
                ax.tick_params(colors='#ffffff', labelsize=9)
                ax.grid(True, axis='y', alpha=0.15, color='#ffffff', linestyle='-', linewidth=0.5)
                # Add value labels on top of bars
                for i, value in enumerate(values):
                    if value > 0:
                        ax.text(i, value, f'{int(value)}', ha='center', va='bottom', 
                               color='#ffffff', fontsize=8)
        elif chart_type == 'line':
            # Line chart - matches dashboard alertsChart and riskTrendChart
            x_pos = range(len(labels))
            # Use color matching the dashboard critical alerts chart
            line_color = 'rgba(255,99,132,0.85)'
            fill_color = 'rgba(255,99,132,0.25)'
            
            # Check title to determine which dashboard chart this represents
            if title and 'risk trend' in title.lower():
                # Overall Risk Trend uses orange
                line_color = 'rgba(255,159,64,0.9)'
                fill_color = 'rgba(255,159,64,0.18)'
            
            # Convert rgba to matplotlib
            def rgba_to_mpl(rgba_str):
                import re
                match = re.search(r'rgba?\((\d+),(\d+),(\d+),?([0-9.]+)?\)', rgba_str)
                if match:
                    r, g, b = int(match.group(1))/255, int(match.group(2))/255, int(match.group(3))/255
                    a = float(match.group(4)) if match.group(4) else 1.0
                    return (r, g, b, a)
                return (0.5, 0.5, 0.5, 1.0)
            
            line_rgb = rgba_to_mpl(line_color)
            fill_rgb = rgba_to_mpl(fill_color)
            
            ax.plot(x_pos, values, marker='o', linewidth=2, color=line_rgb, 
                   markerfacecolor=line_rgb, markersize=4, markeredgewidth=0)
            ax.fill_between(x_pos, values, alpha=fill_rgb[3], color=fill_rgb[:3])
            ax.set_xticks(x_pos)
            ax.set_xticklabels(labels, rotation=0 if len(labels) <= 7 else 45, 
                              ha='center' if len(labels) <= 7 else 'right', 
                              color='#ffffff', fontsize=9)
            ax.set_ylabel('Value', color='#ffffff', fontsize=10)
            ax.tick_params(colors='#ffffff', labelsize=9)
            ax.grid(True, alpha=0.15, color='#ffffff', linestyle='-', linewidth=0.5)
            ax.set_ylim(bottom=0)  # Start from zero like dashboard
        elif chart_type == 'pie':
            # Pie chart - matches dashboard riskChart
            # Color mapping matching dashboard exactly
            colors_pie = {
                'critical': 'rgba(255,99,132,.65)',
                'high': 'rgba(255,140,0,.65)',
                'medium': 'rgba(255,206,86,.65)',
                'low': 'rgba(75,192,192,.65)',
                'zero severity': 'rgba(160,160,160,.65)',
                'unknown': 'rgba(153,102,255,.65)'
            }
            
            def rgba_to_mpl(rgba_str):
                import re
                match = re.search(r'rgba?\((\d+),(\d+),(\d+),?([0-9.]+)?\)', rgba_str)
                if match:
                    r, g, b = int(match.group(1))/255, int(match.group(2))/255, int(match.group(3))/255
                    a = float(match.group(4)) if match.group(4) else 1.0
                    return (r, g, b, a)
                return (0.5, 0.5, 0.5, 0.65)
            
            pie_colors = [rgba_to_mpl(colors_pie.get(str(label).lower(), 'rgba(74,144,226,.65)')) 
                         for label in labels]
            
            wedges, texts, autotexts = ax.pie(values, labels=labels, autopct='%1.1f%%', startangle=90, 
                                              colors=pie_colors, textprops={'color': '#ffffff', 'fontsize': 9})
            for autotext in autotexts:
                autotext.set_color('#ffffff')
                autotext.set_fontweight('bold')
                autotext.set_fontsize(8)
            for text in texts:
                text.set_color('#ffffff')
                text.set_fontsize(9)
            ax.axis('equal')
        
        # Add title if provided (not for pie charts as they don't have titles in dashboard)
        if title and chart_type != 'pie':
            ax.set_title(title, color='#ffffff', fontsize=11, pad=12, fontweight='normal')
        
        # Style the spines to match dashboard
        for spine in ax.spines.values():
            spine.set_edgecolor((1.0, 1.0, 1.0, 0.15))
            spine.set_linewidth(0.5)
        
        # Adjust layout to prevent label cutoff
        plt.tight_layout()
        
        # Save to buffer with settings matching dashboard appearance
        img_buffer = io.BytesIO()
        plt.savefig(img_buffer, format='png', dpi=150, bbox_inches='tight', 
                   facecolor='#23272F', edgecolor='none')
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
