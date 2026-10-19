import { NativeAotArtifactService } from "../application/nativeAot/NativeAotArtifactService.js";
import { NativeAotProvider } from "../dotnet/ManagedNativeAotProvider.js";

/** Compose bundled offline inspection without acquiring a toolchain or starting any process. */
export const createNativeAotArtifactService = (): NativeAotArtifactService =>
  new NativeAotArtifactService(new NativeAotProvider());
