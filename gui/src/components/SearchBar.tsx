import React, { useRef, useEffect } from 'react';
import { Search, X } from 'lucide-react';

interface SearchBarProps {
  searchQuery: string;
  onSearchChange: (query: string) => void;
  activeCategory: string;
  onCategoryChange: (category: string) => void;
  categories: { id: string; label: string; count?: number }[];
}

export const SearchBar: React.FC<SearchBarProps> = ({
  searchQuery,
  onSearchChange,
  activeCategory,
  onCategoryChange,
  categories,
}) => {
  const inputRef = useRef<HTMLInputElement>(null);

  // Global ⌘K shortcut to focus search
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        inputRef.current?.focus();
        inputRef.current?.select();
      }
      if (e.key === 'Escape' && document.activeElement === inputRef.current) {
        if (searchQuery) {
          onSearchChange('');
        } else {
          inputRef.current?.blur();
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [searchQuery, onSearchChange]);

  return (
    <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 select-none">
      {/* Search Input Box */}
      <div className="relative flex-1 max-w-md flex items-center">
        <div className="absolute left-3 flex items-center pointer-events-none text-[#808080]">
          <Search className="w-4 h-4" />
        </div>
        <input
          ref={inputRef}
          type="text"
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Search secrets by name or prefix... (⌘K)"
          className="w-full pl-9 pr-16 py-1.5 bg-surface hover:bg-surface-hover text-white placeholder-[#6E6E73] text-xs font-mono rounded-lg border border-border-subtle focus:border-[#00FF88]/50 focus:ring-1 focus:ring-[#00FF88]/20 focus:outline-none transition-all duration-150 ease-spring"
        />

        {/* Action icons / shortcut hint */}
        <div className="absolute right-2.5 flex items-center gap-1.5">
          {searchQuery ? (
            <button
              onClick={() => onSearchChange('')}
              className="p-1 text-[#808080] hover:text-white rounded cursor-pointer transition-colors"
              title="Clear search (Esc)"
            >
              <X className="w-3 h-3" />
            </button>
          ) : (
            <kbd className="hidden sm:inline-flex items-center px-1.5 py-0.5 text-[10px] font-mono text-[#6E6E73] bg-surface-active rounded border border-border-subtle">
              ⌘K
            </kbd>
          )}
        </div>
      </div>

      {/* Burnrate Segmented Control */}
      <div className="flex items-center gap-1 p-0.5 bg-surface rounded-lg border border-border-subtle text-xs no-scrollbar">
        {categories.map((cat) => {
          const isActive = activeCategory === cat.id;
          return (
            <button
              key={cat.id}
              onClick={() => onCategoryChange(cat.id)}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition-all duration-150 ease-spring whitespace-nowrap cursor-pointer ${
                isActive
                  ? 'bg-surface-active text-white border border-border-track shadow-sm'
                  : 'text-[#808080] hover:text-white'
              }`}
            >
              {cat.label}
              {cat.count !== undefined && (
                <span className="ml-1.5 text-[10px] font-mono opacity-60">({cat.count})</span>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
};
