import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';

// Renders a DOM element to a screenshot-style PDF — used for pages where the visual layout
// (charts, colored badges, cards) matters more than clean text extraction.
export async function exportPageAsPDF(
    elementId: string,
    filename: string,
    title: string
): Promise<void> {
    const element = document.getElementById(elementId);
    if (!element) return;

    const canvas = await html2canvas(element, {
        scale: 2,
        useCORS: true,
        backgroundColor: '#ffffff',
        logging: false,
    });

    const pdf = new jsPDF({
        orientation: 'portrait',
        unit: 'mm',
        format: 'a4',
    });

    const pageWidth = pdf.internal.pageSize.getWidth();
    const pageHeight = pdf.internal.pageSize.getHeight();
    const imgWidth = pageWidth - 20;
    const imgHeight = (canvas.height * imgWidth) / canvas.width;

    // Header
    pdf.setFillColor(82, 3, 133); // #520385
    pdf.rect(0, 0, pageWidth, 20, 'F');
    pdf.setTextColor(255, 255, 255);
    pdf.setFontSize(12);
    pdf.setFont('helvetica', 'bold');
    pdf.text('NovrSOC', 10, 13);
    pdf.setFont('helvetica', 'normal');
    pdf.setFontSize(9);
    pdf.text(`${title} Report`, 35, 13);
    pdf.text(`Generated: ${new Date().toLocaleString()}`, pageWidth - 10, 13, { align: 'right' });

    // Content — sliced into page-height chunks of the source canvas
    let yPosition = 25;
    let remainingHeight = imgHeight;

    while (remainingHeight > 0) {
        const chunkHeight = Math.min(remainingHeight, pageHeight - 30);
        const srcY = (imgHeight - remainingHeight) * (canvas.height / imgHeight);
        const srcHeight = chunkHeight * (canvas.height / imgHeight);

        const chunkCanvas = document.createElement('canvas');
        chunkCanvas.width = canvas.width;
        chunkCanvas.height = srcHeight;
        const ctx = chunkCanvas.getContext('2d');
        if (ctx) {
            ctx.drawImage(canvas, 0, srcY, canvas.width, srcHeight, 0, 0, canvas.width, srcHeight);
            const chunkData = chunkCanvas.toDataURL('image/png');
            pdf.addImage(chunkData, 'PNG', 10, yPosition, imgWidth, chunkHeight);
        }

        remainingHeight -= chunkHeight;
        if (remainingHeight > 0) {
            pdf.addPage();
            yPosition = 10;
        }
    }

    // Footer on last page
    pdf.setFillColor(82, 3, 133);
    pdf.rect(0, pageHeight - 10, pageWidth, 10, 'F');
    pdf.setTextColor(255, 255, 255);
    pdf.setFontSize(7);
    pdf.text('Confidential — NovrSOC by Cybernovr', 10, pageHeight - 3);
    pdf.text('socnovr.vercel.app', pageWidth - 10, pageHeight - 3, { align: 'right' });

    pdf.save(`${filename}-${new Date().toISOString().split('T')[0]}.pdf`);
}

// Simple data-only PDF (no screenshot — faster, cleaner, works with no DOM element at all).
export function exportDataAsPDF(
    title: string,
    filename: string,
    sections: Array<{
        heading: string;
        rows: Array<{ label: string; value: string }>;
    }>
): void {
    const pdf = new jsPDF();
    const pageWidth = pdf.internal.pageSize.getWidth();

    // Header
    pdf.setFillColor(82, 3, 133);
    pdf.rect(0, 0, pageWidth, 25, 'F');
    pdf.setTextColor(255, 255, 255);
    pdf.setFontSize(16);
    pdf.setFont('helvetica', 'bold');
    pdf.text('NovrSOC', 10, 12);
    pdf.setFontSize(10);
    pdf.setFont('helvetica', 'normal');
    pdf.text(title, 10, 20);
    pdf.text(new Date().toLocaleString(), pageWidth - 10, 20, { align: 'right' });

    let y = 35;

    sections.forEach((section) => {
        // Section heading
        pdf.setFillColor(245, 240, 255);
        pdf.rect(10, y - 5, pageWidth - 20, 10, 'F');
        pdf.setTextColor(82, 3, 133);
        pdf.setFontSize(11);
        pdf.setFont('helvetica', 'bold');
        pdf.text(section.heading, 12, y + 2);
        y += 12;

        // Rows
        pdf.setTextColor(28, 31, 46);
        pdf.setFontSize(9);
        pdf.setFont('helvetica', 'normal');

        section.rows.forEach((row) => {
            // Wrap long values instead of letting them run off the page edge invisibly —
            // confirmed as a real defect by rendering actual output: a long narrative or
            // methodology sentence (this function's actual callers include case reports, not
            // just demo documents) was silently clipped at the right margin with no sign
            // anything was cut, rather than being plainly unreadable.
            const valueLines: string[] = pdf.splitTextToSize(row.value, pageWidth - 70 - 10);
            const rowHeight = Math.max(7, valueLines.length * 6 + 1);
            // A row's label and its value must land on the same page — checked once, before
            // drawing anything for this row, rather than mid-row, which was a second defect:
            // a row starting near the page bottom could draw its label on one page and its
            // (then unlabelled-looking) value on the next.
            if (y + rowHeight - 7 > 270) {
                pdf.addPage();
                y = 20;
            }
            pdf.setFont('helvetica', 'bold');
            pdf.text(row.label + ':', 12, y);
            pdf.setFont('helvetica', 'normal');
            valueLines.forEach((line, i) => pdf.text(line, 70, y + i * 6));
            y += rowHeight;
        });

        y += 5;
    });

    // Footer
    pdf.setFillColor(82, 3, 133);
    pdf.rect(0, 287, pageWidth, 10, 'F');
    pdf.setTextColor(255, 255, 255);
    pdf.setFontSize(7);
    pdf.text('Confidential — NovrSOC by Cybernovr · socnovr.vercel.app', pageWidth / 2, 293, { align: 'center' });

    pdf.save(`${filename}-${new Date().toISOString().split('T')[0]}.pdf`);
}
