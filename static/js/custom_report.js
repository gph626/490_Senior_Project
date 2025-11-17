// Custom Report Builder JavaScript
let elements = [];
let currentElementIndex = null;
let currentReportId = null; // Track if we're editing a saved report

// Check if we're loading a saved report
function checkLoadReport() {
    const urlParams = new URLSearchParams(window.location.search);
    const loadId = urlParams.get('load');
    
    if (loadId) {
        loadSavedReport(loadId);
    }
}

// Load a saved report
async function loadSavedReport(reportId) {
    try {
        const response = await fetch(`/api/reports/saved/${reportId}`);
        if (!response.ok) {
            alert('Failed to load saved report');
            return;
        }
        
        const config = await response.json();
        
        // Load the configuration
        document.getElementById('reportTitle').value = config.title || 'Custom Report';
        document.getElementById('reportFilename').value = config.filename || 'custom_report';
        elements = config.elements || [];
        currentReportId = reportId;
        
        renderElements();
        
        // Show success message
        alert('Report loaded successfully!');
    } catch (error) {
        alert('Error loading report: ' + error.message);
    }
}

// Save report
async function saveReport() {
    const config = {
        title: document.getElementById('reportTitle').value,
        filename: document.getElementById('reportFilename').value,
        elements: elements
    };
    
    if (!config.title) {
        alert('Please enter a report title');
        return;
    }
    
    try {
        const response = await fetch('/api/reports/save', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(config)
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentReportId = data.id;
            alert('Report saved successfully!');
        } else {
            alert('Failed to save report: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        alert('Error saving report: ' + error.message);
    }
}

// Add a new element to the canvas
function addElement(type) {
    const element = {
        type: type,
        id: Date.now() + Math.random()
    };

    // Set defaults based on type
    switch(type) {
        case 'title':
            element.text = 'Title Text';
            element.fontSize = 24;
            element.alignment = 'center';
            break;
        case 'heading':
            element.text = 'Heading Text';
            element.fontSize = 16;
            element.alignment = 'left';
            break;
        case 'paragraph':
            element.text = 'Paragraph text goes here. You can add multiple sentences and it will wrap automatically in the PDF.';
            element.fontSize = 11;
            element.alignment = 'left';
            break;
        case 'image':
            element.width = 4;
            element.height = 3;
            element.caption = '';
            element.data = '';
            break;
        case 'spacer':
            element.height = 0.5;
            break;
        case 'pageBreak':
            // No additional properties needed
            break;
    }

    elements.push(element);
    renderElements();
}

// Add chart element - opens modal immediately
function addChartElement() {
    // Just open the modal to let user select charts
    const modal = document.getElementById('chartModal');
    modal.classList.add('active');
}

// Render all elements in the canvas
function renderElements() {
    const container = document.getElementById('elementsContainer');
    
    if (elements.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fa-regular fa-file"></i>
                <p>No elements yet. Add elements using the tools on the left.</p>
            </div>
        `;
        return;
    }

    container.innerHTML = '';
    
    elements.forEach((element, index) => {
        const card = document.createElement('div');
        card.className = 'element-card';
        card.innerHTML = `
            <div class="element-header">
                <span class="element-type">${element.type}</span>
                <div class="element-actions">
                    <button onclick="moveElement(${index}, 'up')" ${index === 0 ? 'disabled' : ''}>
                        <i class="fa-solid fa-arrow-up"></i>
                    </button>
                    <button onclick="moveElement(${index}, 'down')" ${index === elements.length - 1 ? 'disabled' : ''}>
                        <i class="fa-solid fa-arrow-down"></i>
                    </button>
                    <button onclick="editElement(${index})">
                        <i class="fa-solid fa-pen"></i>
                    </button>
                    <button onclick="deleteElement(${index})">
                        <i class="fa-solid fa-trash"></i>
                    </button>
                </div>
            </div>
            <div class="element-preview">
                ${getElementPreview(element)}
            </div>
        `;
        container.appendChild(card);
    });
}

// Get preview text for an element
function getElementPreview(element) {
    switch(element.type) {
        case 'title':
        case 'heading':
        case 'paragraph':
            return `<small style="color: #ffffff;">${truncate(element.text, 60)}</small>`;
        case 'chart':
            return `<small style="color: #ffffff;">${element.chartType} chart: ${element.title}</small>`;
        case 'image':
            return `<small style="color: #ffffff;">Image ${element.caption ? '- ' + element.caption : ''}</small>`;
        case 'spacer':
            return `<small style="color: #ffffff;">Spacer: ${element.height} inches</small>`;
        case 'pageBreak':
            return `<small style="color: #ffffff;">Page break</small>`;
        default:
            return '';
    }
}

// Truncate text for preview
function truncate(str, length) {
    return str.length > length ? str.substring(0, length) + '...' : str;
}

// Move element up or down
function moveElement(index, direction) {
    if (direction === 'up' && index > 0) {
        [elements[index], elements[index - 1]] = [elements[index - 1], elements[index]];
    } else if (direction === 'down' && index < elements.length - 1) {
        [elements[index], elements[index + 1]] = [elements[index + 1], elements[index]];
    }
    renderElements();
}

// Edit an element
function editElement(index) {
    currentElementIndex = index;
    const element = elements[index];
    
    if (element.type === 'chart') {
        showChartModal(element);
    } else if (element.type === 'image') {
        showImageUpload(element);
    } else {
        showEditForm(element);
    }
}

// Show edit form for text elements
function showEditForm(element) {
    const container = document.getElementById('elementsContainer');
    const card = container.children[currentElementIndex];
    
    let formHTML = '';
    
    if (element.type === 'title' || element.type === 'heading' || element.type === 'paragraph') {
        formHTML = `
            <div class="form-group">
                <label>Text</label>
                <textarea id="editText">${element.text}</textarea>
            </div>
            <div class="form-group">
                <label>Font Size</label>
                <input type="number" id="editFontSize" value="${element.fontSize}" min="8" max="48">
            </div>
            <div class="form-group">
                <label>Alignment</label>
                <select id="editAlignment">
                    <option value="left" ${element.alignment === 'left' ? 'selected' : ''}>Left</option>
                    <option value="center" ${element.alignment === 'center' ? 'selected' : ''}>Center</option>
                    <option value="right" ${element.alignment === 'right' ? 'selected' : ''}>Right</option>
                </select>
            </div>
        `;
    } else if (element.type === 'spacer') {
        formHTML = `
            <div class="form-group">
                <label>Height (inches)</label>
                <input type="number" id="editHeight" value="${element.height}" min="0.1" max="5" step="0.1">
            </div>
        `;
    }
    
    formHTML += `
        <div style="display: flex; gap: 10px; margin-top: 10px;">
            <button onclick="saveEdit()" style="flex: 1; padding: 8px; background: var(--primary-color); color: white; border: none; border-radius: 4px; cursor: pointer;">Save</button>
            <button onclick="cancelEdit()" style="flex: 1; padding: 8px; background: #666; color: white; border: none; border-radius: 4px; cursor: pointer;">Cancel</button>
        </div>
    `;
    
    card.innerHTML = `
        <div class="element-header">
            <span class="element-type" style="color: #ffffff;">Editing ${element.type}</span>
        </div>
        ${formHTML}
    `;
}

// Save edited element
function saveEdit() {
    const element = elements[currentElementIndex];
    
    if (element.type === 'title' || element.type === 'heading' || element.type === 'paragraph') {
        element.text = document.getElementById('editText').value;
        element.fontSize = parseInt(document.getElementById('editFontSize').value);
        element.alignment = document.getElementById('editAlignment').value;
    } else if (element.type === 'spacer') {
        element.height = parseFloat(document.getElementById('editHeight').value);
    }
    
    currentElementIndex = null;
    renderElements();
}

// Cancel edit
function cancelEdit() {
    currentElementIndex = null;
    renderElements();
}

// Delete an element
function deleteElement(index) {
    if (confirm('Are you sure you want to delete this element?')) {
        elements.splice(index, 1);
        renderElements();
    }
}

// Show chart configuration modal
function showChartModal(element) {
    const modal = document.getElementById('chartModal');
    const form = document.getElementById('chartConfigForm');
    
    form.innerHTML = `
        <div class="form-group">
            <label>Selected Chart: <span id="chartTypeDisplay">None - Please load data below</span></label>
        </div>
        <div class="form-group">
            <label>Width (inches)</label>
            <input type="number" id="chartWidth" value="${element.width}" min="2" max="7" step="0.5">
        </div>
        <div class="form-group">
            <label>Height (inches)</label>
            <input type="number" id="chartHeight" value="${element.height}" min="2" max="7" step="0.5">
        </div>
        <div style="display: flex; gap: 10px; margin-top: 20px;">
            <button type="button" onclick="saveChart()" style="flex: 1; padding: 10px; background: var(--primary-color); color: white; border: none; border-radius: 4px; cursor: pointer;">Save Chart</button>
            <button type="button" onclick="cancelChartModal()" style="flex: 1; padding: 10px; background: #666; color: white; border: none; border-radius: 4px; cursor: pointer;">Cancel</button>
        </div>
    `;
    
    // Update display if data already loaded
    if (element.title) {
        document.getElementById('chartTypeDisplay').textContent = element.title;
    }
    
    modal.classList.add('active');
}

// Cancel chart modal
function cancelChartModal() {
    // If data is empty, remove the element
    const element = elements[currentElementIndex];
    if (element && !element.dataLoaded) {
        elements.splice(currentElementIndex, 1);
        renderElements();
    }
    closeModal('chartModal');
}

// Load chart data from various endpoints
async function loadChartData(dataType) {
    const element = elements[currentElementIndex];
    
    const endpoints = {
        'leaks_per_crawler': {
            url: '/api/reports/data/leaks_per_crawler',
            title: 'Leaks per Crawler',
            chartType: 'bar'
        },
        'critical_alerts': {
            url: '/api/reports/data/critical_alerts',
            title: 'Critical Alerts Over Time',
            chartType: 'line'
        },
        'risk_severity': {
            url: '/api/reports/data/risk_severity',
            title: 'Risk Severity Breakdown',
            chartType: 'pie'
        },
        'risk_trend': {
            url: '/api/reports/data/risk_trend?days=7',
            title: 'Overall Risk Trend (7 Days)',
            chartType: 'line'
        },
        'severity_trend': {
            url: '/api/reports/data/severity_trend?days=7',
            title: 'Risk by Severity Over Time',
            chartType: 'line'
        },
        'top_assets_type': {
            url: '/api/reports/data/top_assets?mode=type&limit=10',
            title: 'Top Risky Assets by Type',
            chartType: 'bar'
        },
        'top_assets_asset': {
            url: '/api/reports/data/top_assets?mode=asset&limit=10',
            title: 'Top Risky Assets',
            chartType: 'bar'
        }
    };
    
    const config = endpoints[dataType];
    if (!config) {
        alert('Unknown data type');
        return;
    }
    
    try {
        const response = await fetch(config.url);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            const text = await response.text();
            throw new Error(`Expected JSON but got: ${text.substring(0, 100)}`);
        }
        
        const data = await response.json();
        
        // Check if the response contains an error
        if (data.error) {
            throw new Error(data.error);
        }
        
        // Store the loaded data
        element.data = data;
        element.title = config.title;
        element.chartType = config.chartType;
        element.dataLoaded = true; // Flag to track successful load
        
        // Update display
        const displayElement = document.getElementById('chartTypeDisplay');
        if (displayElement) {
            displayElement.textContent = config.title;
        }
        
        alert(`Chart data loaded: ${config.title}`);
    } catch (error) {
        console.error('Load chart data error:', error);
        alert('Failed to load data: ' + error.message);
    }
}

// Add selected charts all at once
async function addSelectedCharts() {
    const checkboxes = document.querySelectorAll('input[name="chartSelect"]:checked');
    
    if (checkboxes.length === 0) {
        alert('Please select at least one chart');
        return;
    }
    
    const width = parseFloat(document.getElementById('chartWidth').value);
    const height = parseFloat(document.getElementById('chartHeight').value);
    
    const endpoints = {
        'leaks_per_crawler': {
            url: '/api/reports/data/leaks_per_crawler',
            title: 'Leaks per Crawler',
            chartType: 'bar'
        },
        'critical_alerts': {
            url: '/api/reports/data/critical_alerts',
            title: 'Critical Alerts Over Time',
            chartType: 'line'
        },
        'risk_severity': {
            url: '/api/reports/data/risk_severity',
            title: 'Risk Severity Breakdown',
            chartType: 'pie'
        },
        'risk_trend': {
            url: '/api/reports/data/risk_trend?days=7',
            title: 'Overall Risk Trend (7 Days)',
            chartType: 'line'
        },
        'severity_trend': {
            url: '/api/reports/data/severity_trend?days=7',
            title: 'Risk by Severity Over Time',
            chartType: 'line'
        },
        'top_assets_type': {
            url: '/api/reports/data/top_assets?mode=type&limit=10',
            title: 'Top Risky Assets by Type',
            chartType: 'bar'
        },
        'top_assets_asset': {
            url: '/api/reports/data/top_assets?mode=asset&limit=10',
            title: 'Top Risky Assets',
            chartType: 'bar'
        }
    };
    
    let successCount = 0;
    let failCount = 0;
    
    // Load all selected charts
    for (const checkbox of checkboxes) {
        const dataType = checkbox.value;
        const config = endpoints[dataType];
        
        if (!config) continue;
        
        try {
            const response = await fetch(config.url);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.error) {
                throw new Error(data.error);
            }
            
            // Create and add the chart element
            const element = {
                type: 'chart',
                id: Date.now() + Math.random(),
                chartType: config.chartType,
                title: config.title,
                width: width,
                height: height,
                data: data,
                dataLoaded: true
            };
            
            elements.push(element);
            successCount++;
            
        } catch (error) {
            console.error(`Failed to load ${config.title}:`, error);
            failCount++;
        }
    }
    
    // Update UI
    renderElements();
    closeModal('chartModal');
    
    // Uncheck all checkboxes
    checkboxes.forEach(cb => cb.checked = false);
    
    // Show result
    if (successCount > 0) {
        alert(`Successfully added ${successCount} chart(s)${failCount > 0 ? ` (${failCount} failed)` : ''}`);
    } else {
        alert('Failed to add any charts');
    }
}

// Add new data point
function addDataPoint() {
    const element = elements[currentElementIndex];
    element.data.labels.push('Label');
    element.data.values.push(0);
    renderDataPoints(element.data);
}

// Remove data point
function removeDataPoint(index) {
    const element = elements[currentElementIndex];
    element.data.labels.splice(index, 1);
    element.data.values.splice(index, 1);
    renderDataPoints(element.data);
}

// Save chart configuration
function saveChart() {
    const element = elements[currentElementIndex];
    
    element.width = parseFloat(document.getElementById('chartWidth').value);
    element.height = parseFloat(document.getElementById('chartHeight').value);
    
    // Validate that data has been loaded using the flag
    if (!element.dataLoaded) {
        alert('Please load chart data using one of the "Load Chart Data" buttons before saving.');
        return;
    }
    
    closeModal('chartModal');
    renderElements();
}

// Show image upload for image elements
function showImageUpload(element) {
    const container = document.getElementById('elementsContainer');
    const card = container.children[currentElementIndex];
    
    card.innerHTML = `
        <div class="element-header">
            <span class="element-type">Editing Image</span>
        </div>
        <div class="form-group">
            <label>Upload Image</label>
            <input type="file" id="imageFile" accept="image/*" onchange="handleImageUpload(event)">
        </div>
        <div class="form-group">
            <label>Width (inches)</label>
            <input type="number" id="imageWidth" value="${element.width}" min="1" max="7" step="0.5">
        </div>
        <div class="form-group">
            <label>Height (inches)</label>
            <input type="number" id="imageHeight" value="${element.height}" min="1" max="7" step="0.5">
        </div>
        <div class="form-group">
            <label>Caption</label>
            <input type="text" id="imageCaption" value="${element.caption}" placeholder="Optional caption">
        </div>
        ${element.data ? '<div><img src="data:image/png;base64,' + element.data + '" style="max-width: 100%; margin: 10px 0;"></div>' : ''}
        <div style="display: flex; gap: 10px; margin-top: 10px;">
            <button onclick="saveImage()" style="flex: 1; padding: 8px; background: var(--primary-color); color: white; border: none; border-radius: 4px; cursor: pointer;">Save</button>
            <button onclick="cancelEdit()" style="flex: 1; padding: 8px; background: #666; color: white; border: none; border-radius: 4px; cursor: pointer;">Cancel</button>
        </div>
    `;
}

// Handle image upload
function handleImageUpload(event) {
    const file = event.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = function(e) {
            const element = elements[currentElementIndex];
            element.data = e.target.result.split(',')[1]; // Store base64 without prefix
            showImageUpload(element); // Re-render to show preview
        };
        reader.readAsDataURL(file);
    }
}

// Save image element
function saveImage() {
    const element = elements[currentElementIndex];
    element.width = parseFloat(document.getElementById('imageWidth').value);
    element.height = parseFloat(document.getElementById('imageHeight').value);
    element.caption = document.getElementById('imageCaption').value;
    
    currentElementIndex = null;
    renderElements();
}

// Close modal
function closeModal(modalId) {
    document.getElementById(modalId).classList.remove('active');
    currentElementIndex = null;
}

// Generate preview
async function generatePreview() {
    const config = {
        title: document.getElementById('reportTitle').value,
        filename: document.getElementById('reportFilename').value,
        elements: elements
    };
    
    const previewContainer = document.getElementById('previewContainer');
    previewContainer.innerHTML = '<p>Generating preview...</p>';
    
    try {
        const response = await fetch('/api/reports/preview', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(config)
        });
        
        const data = await response.json();
        
        if (data.success) {
            previewContainer.innerHTML = `
                <iframe class="pdf-preview" src="data:application/pdf;base64,${data.pdf_data}"></iframe>
            `;
        } else {
            previewContainer.innerHTML = `<p style="color: #ffffff;">Error: ${data.error}</p>`;
        }
    } catch (error) {
        previewContainer.innerHTML = `<p style="color: #ffffff;">Error generating preview: ${error.message}</p>`;
    }
}

// Download PDF
async function downloadPDF() {
    const config = {
        title: document.getElementById('reportTitle').value,
        filename: document.getElementById('reportFilename').value,
        elements: elements
    };
    
    try {
        const response = await fetch('/api/reports/download', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(config)
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = config.filename + '.pdf';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        } else {
            alert('Failed to download PDF');
        }
    } catch (error) {
        alert('Error downloading PDF: ' + error.message);
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    renderElements();
    checkLoadReport();
});
