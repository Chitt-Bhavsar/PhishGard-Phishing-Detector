import React, { useEffect, useRef } from 'react';
import h337 from 'heatmap.js';

interface HeatMapProps {
  data: Array<{
    date: string;
    count: number;
  }>;
}

const HeatMap: React.FC<HeatMapProps> = ({ data }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const heatmapRef = useRef<any>(null);

  useEffect(() => {
    if (!containerRef.current || !data.length) return;

    // Clear previous heatmap if it exists
    if (containerRef.current.firstChild) {
      containerRef.current.innerHTML = '';
    }

    // Create a new heatmap instance
    heatmapRef.current = h337.create({
      container: containerRef.current,
      radius: 20,
      maxOpacity: 0.8,
      minOpacity: 0.1,
      blur: 0.8,
      gradient: {
        0.4: 'blue',
        0.6: 'cyan',
        0.7: 'lime',
        0.8: 'yellow',
        1.0: 'red'
      }
    });

    // Calculate the width of each day cell
    const containerWidth = containerRef.current.offsetWidth;
    const cellWidth = containerWidth / 30; // 30 days
    const containerHeight = containerRef.current.offsetHeight;

    // Find the maximum count to normalize the data
    const maxCount = Math.max(...data.map(item => item.count));

    // Generate heatmap data points
    const points = data.map((item, index) => {
      const value = item.count;
      const normalizedValue = maxCount > 0 ? (value / maxCount) * 100 : 0;
      
      return {
        x: Math.floor(index * cellWidth + cellWidth / 2),
        y: Math.floor(containerHeight / 2),
        value: normalizedValue,
        radius: 20
      };
    });

    // Set the data
    heatmapRef.current.setData({
      max: 100,
      data: points
    });

    // Add date labels
    const labelsContainer = document.createElement('div');
    labelsContainer.className = 'absolute bottom-0 left-0 right-0 flex justify-between px-4 text-xs text-gray-500';
    
    // Add only a few labels to avoid overcrowding
    [0, 9, 19, 29].forEach(index => {
      if (data[index]) {
        const label = document.createElement('div');
        const date = new Date(data[index].date);
        label.textContent = `${date.getMonth() + 1}/${date.getDate()}`;
        label.style.position = 'absolute';
        label.style.left = `${(index * cellWidth / containerWidth) * 100}%`;
        labelsContainer.appendChild(label);
      }
    });
    
    containerRef.current.appendChild(labelsContainer);

  }, [data]);

  return (
    <div className="relative w-full h-full">
      <div ref={containerRef} className="w-full h-full"></div>
    </div>
  );
};

export default HeatMap;