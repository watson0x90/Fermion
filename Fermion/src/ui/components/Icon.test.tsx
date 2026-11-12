import { render } from '@testing-library/react';
import { Icon } from './Icon';

test('Icon renders an inline svg tagged with its name and uses currentColor', () => {
  const { container } = render(<Icon name="session" />);
  const svg = container.querySelector('svg');
  expect(svg).toBeInTheDocument();
  expect(svg).toHaveAttribute('data-icon', 'session');
  expect(svg).toHaveAttribute('stroke', 'currentColor');
  // has drawn geometry
  expect(svg!.querySelector('rect, path, circle, ellipse')).toBeTruthy();
});

test('Icon size prop sets width/height', () => {
  const { container } = render(<Icon name="close" size={18} />);
  const svg = container.querySelector('svg')!;
  expect(svg).toHaveAttribute('width', '18');
  expect(svg).toHaveAttribute('height', '18');
});
