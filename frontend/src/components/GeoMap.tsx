import "leaflet/dist/leaflet.css";
import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet";
import { MapPin } from "lucide-react";

export interface GeoLocation {
  lat: number;
  lon: number;
  city: string;
  region: string;
  country: string;
  country_code: string;
  org?: string;
  resolved_ip?: string;
}

interface GeoMapProps {
  geo: GeoLocation;
  iocValue: string;
}

export default function GeoMap({ geo, iocValue }: GeoMapProps) {
  const label = [geo.city, geo.region, geo.country].filter(Boolean).join(", ");

  return (
    <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-5">
      <div className="flex items-center gap-2 mb-4">
        <MapPin size={15} className="text-blue-400" />
        <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
          Geolocalización
        </h2>
      </div>

      <div className="flex flex-wrap gap-4 mb-4 text-sm">
        <span className="text-gray-300">
          <span className="text-gray-500 mr-1">Ubicación:</span>
          {label || "Desconocida"}
        </span>
        {geo.resolved_ip && (
          <span className="text-gray-300">
            <span className="text-gray-500 mr-1">IP resuelta:</span>
            {geo.resolved_ip}
          </span>
        )}
        {geo.org && (
          <span className="text-gray-300">
            <span className="text-gray-500 mr-1">Organización:</span>
            {geo.org}
          </span>
        )}
      </div>

      <div className="rounded-xl overflow-hidden" style={{ height: "280px" }}>
        <MapContainer
          center={[geo.lat, geo.lon]}
          zoom={5}
          style={{ height: "100%", width: "100%" }}
          scrollWheelZoom={false}
        >
          <TileLayer
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
          />
          <CircleMarker
            center={[geo.lat, geo.lon]}
            radius={10}
            pathOptions={{ color: "#3b82f6", fillColor: "#3b82f6", fillOpacity: 0.7 }}
          >
            <Popup>
              <span className="font-mono text-xs">{iocValue}</span>
              <br />
              {label}
            </Popup>
          </CircleMarker>
        </MapContainer>
      </div>
    </div>
  );
}
